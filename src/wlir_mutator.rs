use std::{borrow::Cow, num::NonZeroUsize};

use libafl::{
    corpus::CorpusId,
    mutators::{MutationResult, Mutator},
    state::HasRand,
    Error,
};
use libafl_bolts::{rands::Rand, Named};
use wl_repeater::{
    message::WaylandMessage,
    protocol::Protocol,
    symbolic::{MessageBody, SymbolicSession, Value},
};

use crate::wlir_input::WlirInput;

const MAX_TIMESTAMP_JITTER_US: u64 = 5_000;
const MAX_OBJECT_ID_DELTA: u32 = 8;
const MAX_OPCODE_DELTA: u16 = 4;

pub struct WlirMutator {
    protocol: Protocol,
}

impl WlirMutator {
    pub fn new(protocol: Protocol) -> Self {
        Self { protocol }
    }
}

impl Named for WlirMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("WlirMutator");
        &NAME
    }
}

impl<S> Mutator<WlirInput, S> for WlirMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut WlirInput) -> Result<MutationResult, Error> {
        let mut available_ops = vec![
            MutationOp::ReceiverSubstitution,
            MutationOp::ObjectArgSubstitution,
            MutationOp::Duplicate,
            MutationOp::TimestampJitter,
        ];

        if input.messages.len() > 1 {
            available_ops.push(MutationOp::RemoveOne);
            available_ops.push(MutationOp::SwapAdjacent);
        }

        if available_ops.is_empty() {
            return Ok(MutationResult::Skipped);
        }

        let idx = state
            .rand_mut()
            .below(NonZeroUsize::new(available_ops.len()).unwrap());
        let op = available_ops[idx];

        let result = match op {
            MutationOp::ReceiverSubstitution => {
                substitute_receiver_same_interface(state, input, &self.protocol)
            }
            MutationOp::ObjectArgSubstitution => {
                substitute_object_arg_same_interface(state, input, &self.protocol)
            }
            MutationOp::RemoveOne => remove_one_message(state, input),
            MutationOp::Duplicate => duplicate_one_message(state, input),
            MutationOp::SwapAdjacent => swap_adjacent_messages(state, input),
            MutationOp::TimestampJitter => jitter_timestamp_bounded(state, input),
        };

        Ok(result)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum MutationOp {
    ReceiverSubstitution,
    ObjectArgSubstitution,
    RemoveOne,
    Duplicate,
    SwapAdjacent,
    TimestampJitter,
}

pub(crate) fn remove_one_message<S: HasRand>(
    state: &mut S,
    input: &mut WlirInput,
) -> MutationResult {
    if input.messages.len() <= 1 {
        return MutationResult::Skipped;
    }

    let remove_idx = state
        .rand_mut()
        .below(NonZeroUsize::new(input.messages.len()).unwrap());
    input.messages.remove(remove_idx);
    MutationResult::Mutated
}

pub(crate) fn duplicate_one_message<S: HasRand>(
    state: &mut S,
    input: &mut WlirInput,
) -> MutationResult {
    if input.messages.is_empty() {
        return MutationResult::Skipped;
    }

    let src_idx = state
        .rand_mut()
        .below(NonZeroUsize::new(input.messages.len()).unwrap());
    let duplicate = input.messages[src_idx].clone();
    input.messages.insert(src_idx + 1, duplicate);
    MutationResult::Mutated
}

pub(crate) fn swap_adjacent_messages<S: HasRand>(
    state: &mut S,
    input: &mut WlirInput,
) -> MutationResult {
    if input.messages.len() < 2 {
        return MutationResult::Skipped;
    }

    let left_idx = state
        .rand_mut()
        .below(NonZeroUsize::new(input.messages.len() - 1).unwrap());
    input.messages.swap(left_idx, left_idx + 1);
    MutationResult::Mutated
}

pub(crate) fn jitter_timestamp_bounded<S: HasRand>(
    state: &mut S,
    input: &mut WlirInput,
) -> MutationResult {
    if input.messages.is_empty() {
        return MutationResult::Skipped;
    }

    let index = state
        .rand_mut()
        .below(NonZeroUsize::new(input.messages.len()).unwrap());

    let delta = state
        .rand_mut()
        .between(1, MAX_TIMESTAMP_JITTER_US as usize) as u64;

    let message = &mut input.messages[index];
    if state.rand_mut().coinflip(0.5) {
        message.timestamp_us = message.timestamp_us.saturating_add(delta);
    } else {
        message.timestamp_us = message.timestamp_us.saturating_sub(delta);
    }

    MutationResult::Mutated
}

pub(crate) fn substitute_receiver_same_interface<S: HasRand>(
    state: &mut S,
    input: &mut WlirInput,
    protocol: &Protocol,
) -> MutationResult {
    let mut session = SymbolicSession::import(&input.header, &input.messages, protocol);
    let semantic_indexes: Vec<_> = session
        .messages
        .iter()
        .enumerate()
        .filter_map(|(index, message)| match &message.body {
            MessageBody::Semantic(call) => {
                Some((index, message.receiver, call.interface, message.id))
            }
            MessageBody::Raw(_) => None,
        })
        .collect();

    for (index, receiver, interface, message_id) in semantic_indexes {
        let alternatives: Vec<_> = session
            .symbols
            .iter()
            .filter(|symbol| {
                symbol.id != receiver
                    && symbol.interface == interface
                    && symbol.is_live_at(message_id)
            })
            .map(|symbol| symbol.id)
            .collect();
        if alternatives.is_empty() {
            continue;
        }
        let choice = state
            .rand_mut()
            .below(NonZeroUsize::new(alternatives.len()).unwrap());
        session.messages[index].receiver = alternatives[choice];
        input.messages = session.lower(protocol);
        return MutationResult::Mutated;
    }

    MutationResult::Skipped
}

pub(crate) fn substitute_object_arg_same_interface<S: HasRand>(
    state: &mut S,
    input: &mut WlirInput,
    protocol: &Protocol,
) -> MutationResult {
    let mut session = SymbolicSession::import(&input.header, &input.messages, protocol);

    for message_index in 0..session.messages.len() {
        let (message_id, object_args): (u32, Vec<(usize, u32)>) =
            match &session.messages[message_index].body {
                MessageBody::Semantic(call) => (
                    session.messages[message_index].id,
                    call.args
                        .iter()
                        .enumerate()
                        .filter_map(|(arg_index, arg)| match &arg.value {
                            Value::Object(current) => Some((arg_index, *current)),
                            _ => None,
                        })
                        .collect(),
                ),
                MessageBody::Raw(_) => continue,
            };

        for (arg_index, current) in object_args {
            let current_interface = session.symbols[current as usize].interface;
            let alternatives: Vec<_> = session
                .symbols
                .iter()
                .filter(|symbol| {
                    symbol.id != current
                        && symbol.interface == current_interface
                        && symbol.is_live_at(message_id)
                })
                .map(|symbol| symbol.id)
                .collect();
            if alternatives.is_empty() {
                continue;
            }

            let choice = state
                .rand_mut()
                .below(NonZeroUsize::new(alternatives.len()).unwrap());
            let replacement = alternatives[choice];

            if let MessageBody::Semantic(call) = &mut session.messages[message_index].body {
                call.args[arg_index].value = Value::Object(replacement);
            }

            input.messages = session.lower(protocol);
            return MutationResult::Mutated;
        }
    }

    MutationResult::Skipped
}

fn sync_wire_header(message: &mut WaylandMessage) {
    if message.wire_data.len() >= 4 {
        message.wire_data[0..4].copy_from_slice(&message.object_id.to_le_bytes());
    }

    if message.wire_data.len() >= 6 {
        message.wire_data[4..6].copy_from_slice(&message.opcode.to_le_bytes());
    }

    // TODO(boundary): argument-aware mutation.
    // TODO(boundary): protocol-aware message synthesis.
    // TODO(boundary): connection reuse / repeater reset.
    // TODO(boundary): replay duration and message-count caps.
    // TODO(boundary): smarter ownership to avoid cloning large message vectors.
    // We intentionally do not alter `wire_data[8..]`, FD content, or FD update payloads.
}

#[cfg(test)]
mod tests {
    use super::*;
    use libafl_bolts::rands::StdRand;
    use wl_repeater::protocol::Protocol;
    use wl_repeater::{
        ir::IrFileHeader,
        message::{Direction, FdRecord, FdType, FdUpdateRecord},
    };

    const MINI_XML: &str = r#"<?xml version="1.0"?>
<protocol name="mini">
  <interface name="wl_display" version="1">
    <request name="make_child">
      <arg name="id" type="new_id" interface="wl_child"/>
    </request>
  </interface>
  <interface name="wl_child" version="1">
    <request name="ping"/>
    <request name="link">
      <arg name="peer" type="object" interface="wl_child"/>
    </request>
  </interface>
</protocol>"#;

    fn mk_message(timestamp_us: u64, object_id: u32, opcode: u16) -> WaylandMessage {
        WaylandMessage {
            timestamp_us,
            instance_id: 0,
            object_id,
            opcode,
            direction: Direction::ClientToServer,
            wire_data: [
                object_id.to_le_bytes().as_slice(),
                opcode.to_le_bytes().as_slice(),
                (8u16).to_le_bytes().as_slice(),
            ]
            .concat(),
            fds: vec![FdRecord {
                fd_num: 4,
                fd_type: FdType::Shm,
                seekable: true,
                truncated: false,
                format_hint: 0,
                original_size: 4,
                content: vec![1, 2, 3, 4],
            }],
            fd_updates: vec![FdUpdateRecord {
                object_id,
                new_size: 4,
                content: vec![9, 8, 7, 6],
            }],
            decoded_args: Vec::new(),
        }
    }

    fn mk_input() -> WlirInput {
        WlirInput {
            header: IrFileHeader {
                magic: 0x574C_4952,
                version: 2,
                start_time_us: 10,
                flags: 0,
                reserved: 0,
            },
            messages: vec![
                mk_message(10, 1, 2),
                mk_message(20, 3, 4),
                mk_message(30, 5, 6),
            ],
        }
    }

    struct TestRandState {
        rand: StdRand,
    }

    impl HasRand for TestRandState {
        type Rand = StdRand;

        fn rand(&self) -> &Self::Rand {
            &self.rand
        }

        fn rand_mut(&mut self) -> &mut Self::Rand {
            &mut self.rand
        }
    }

    fn mk_state(seed: u64) -> TestRandState {
        TestRandState {
            rand: StdRand::with_seed(seed),
        }
    }

    fn protocol() -> Protocol {
        let mut protocol = Protocol::new();
        protocol.load_str(MINI_XML).unwrap();
        protocol
    }

    fn mk_semantic_input_for_receiver_substitution() -> WlirInput {
        WlirInput {
            header: IrFileHeader {
                magic: 0x574C_4952,
                version: 2,
                start_time_us: 10,
                flags: 0,
                reserved: 0,
            },
            messages: vec![
                WaylandMessage {
                    timestamp_us: 10,
                    instance_id: 0,
                    object_id: 1,
                    opcode: 0,
                    direction: Direction::ClientToServer,
                    wire_data: [
                        1u32.to_le_bytes().as_slice(),
                        0u16.to_le_bytes().as_slice(),
                        (12u16).to_le_bytes().as_slice(),
                        2u32.to_le_bytes().as_slice(),
                    ]
                    .concat(),
                    fds: Vec::new(),
                    fd_updates: Vec::new(),
                    decoded_args: Vec::new(),
                },
                WaylandMessage {
                    timestamp_us: 20,
                    instance_id: 0,
                    object_id: 1,
                    opcode: 0,
                    direction: Direction::ClientToServer,
                    wire_data: [
                        1u32.to_le_bytes().as_slice(),
                        0u16.to_le_bytes().as_slice(),
                        (12u16).to_le_bytes().as_slice(),
                        3u32.to_le_bytes().as_slice(),
                    ]
                    .concat(),
                    fds: Vec::new(),
                    fd_updates: Vec::new(),
                    decoded_args: Vec::new(),
                },
                WaylandMessage {
                    timestamp_us: 30,
                    instance_id: 0,
                    object_id: 2,
                    opcode: 0,
                    direction: Direction::ClientToServer,
                    wire_data: [
                        2u32.to_le_bytes().as_slice(),
                        0u16.to_le_bytes().as_slice(),
                        (8u16).to_le_bytes().as_slice(),
                    ]
                    .concat(),
                    fds: Vec::new(),
                    fd_updates: Vec::new(),
                    decoded_args: Vec::new(),
                },
            ],
        }
    }

    #[test]
    fn structural_mutation_preserves_wlir_round_tripability() {
        let mut input = mk_input();
        let mut state = mk_state(0x1234);
        let _ = duplicate_one_message(&mut state, &mut input);
        let bytes = input.to_wlir_bytes();
        assert!(WlirInput::from_bytes(bytes.as_slice()).is_ok());
    }

    #[test]
    fn remove_operation_reduces_message_count_when_more_than_one_exists() {
        let mut input = mk_input();
        let mut state = mk_state(0x1234);
        let before = input.messages.len();

        let result = remove_one_message(&mut state, &mut input);

        assert!(matches!(result, MutationResult::Mutated));
        assert_eq!(input.messages.len(), before - 1);
    }

    #[test]
    fn duplicate_operation_increases_message_count() {
        let mut input = mk_input();
        let mut state = mk_state(0x5678);
        let before = input.messages.len();

        let result = duplicate_one_message(&mut state, &mut input);

        assert!(matches!(result, MutationResult::Mutated));
        assert_eq!(input.messages.len(), before + 1);
    }

    #[test]
    fn swap_adjacent_operation_reorders_neighbors() {
        let mut input = mk_input();
        let mut state = mk_state(0x9abc);
        let before = input
            .messages
            .iter()
            .map(|m| (m.timestamp_us, m.object_id, m.opcode))
            .collect::<Vec<_>>();

        let result = swap_adjacent_messages(&mut state, &mut input);

        assert!(matches!(result, MutationResult::Mutated));
        let after = input
            .messages
            .iter()
            .map(|m| (m.timestamp_us, m.object_id, m.opcode))
            .collect::<Vec<_>>();
        assert_ne!(after, before);
    }

    #[test]
    fn timestamp_jitter_stays_within_bound() {
        let mut input = mk_input();
        let mut state = mk_state(0xdef0);
        let before = input
            .messages
            .iter()
            .map(|m| m.timestamp_us)
            .collect::<Vec<_>>();

        let result = jitter_timestamp_bounded(&mut state, &mut input);

        assert!(matches!(result, MutationResult::Mutated));
        let after = input
            .messages
            .iter()
            .map(|m| m.timestamp_us)
            .collect::<Vec<_>>();
        let mut changed = 0usize;
        for (b, a) in before.iter().zip(after.iter()) {
            if a != b {
                changed += 1;
                assert!(a.abs_diff(*b) <= MAX_TIMESTAMP_JITTER_US);
            }
        }
        assert_eq!(changed, 1);
    }

    #[test]
    fn semantic_receiver_substitution_rewrites_header_object_id() {
        let mut input = mk_semantic_input_for_receiver_substitution();
        let mut state = mk_state(0x9999);

        let result = substitute_receiver_same_interface(&mut state, &mut input, &protocol());

        assert!(matches!(result, MutationResult::Mutated));
        assert_eq!(input.messages[2].object_id, 3);
        assert_eq!(&input.messages[2].wire_data[0..4], &3u32.to_le_bytes());
    }

    #[test]
    fn semantic_object_argument_substitution_rewrites_argument_payload() {
        let mut input = WlirInput {
            header: mk_input().header,
            messages: vec![
                WaylandMessage {
                    timestamp_us: 10,
                    instance_id: 0,
                    object_id: 1,
                    opcode: 0,
                    direction: Direction::ClientToServer,
                    wire_data: [
                        1u32.to_le_bytes().as_slice(),
                        0u16.to_le_bytes().as_slice(),
                        (12u16).to_le_bytes().as_slice(),
                        2u32.to_le_bytes().as_slice(),
                    ]
                    .concat(),
                    fds: Vec::new(),
                    fd_updates: Vec::new(),
                    decoded_args: Vec::new(),
                },
                WaylandMessage {
                    timestamp_us: 20,
                    instance_id: 0,
                    object_id: 1,
                    opcode: 0,
                    direction: Direction::ClientToServer,
                    wire_data: [
                        1u32.to_le_bytes().as_slice(),
                        0u16.to_le_bytes().as_slice(),
                        (12u16).to_le_bytes().as_slice(),
                        3u32.to_le_bytes().as_slice(),
                    ]
                    .concat(),
                    fds: Vec::new(),
                    fd_updates: Vec::new(),
                    decoded_args: Vec::new(),
                },
                WaylandMessage {
                    timestamp_us: 30,
                    instance_id: 0,
                    object_id: 2,
                    opcode: 1,
                    direction: Direction::ClientToServer,
                    wire_data: [
                        2u32.to_le_bytes().as_slice(),
                        1u16.to_le_bytes().as_slice(),
                        (12u16).to_le_bytes().as_slice(),
                        3u32.to_le_bytes().as_slice(),
                    ]
                    .concat(),
                    fds: Vec::new(),
                    fd_updates: Vec::new(),
                    decoded_args: Vec::new(),
                },
            ],
        };
        let mut state = mk_state(0xABCD);

        let result = substitute_object_arg_same_interface(&mut state, &mut input, &protocol());

        assert!(matches!(result, MutationResult::Mutated));
        assert_eq!(&input.messages[2].wire_data[8..12], &2u32.to_le_bytes());
    }
}
