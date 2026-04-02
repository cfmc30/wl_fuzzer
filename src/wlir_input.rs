use std::{
    hash::{Hash, Hasher},
    io,
};

use libafl::inputs::{HasTargetBytes, Input};
use libafl_bolts::{HasLen, ownedref::OwnedSlice};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use wl_repeater::{
    ir::{IrFdInfo, IrFdUpdateRecord, IrFileHeader, IrMessageRecord, IrReader, IrRecordHeader},
    message::{Direction, FdRecord, WaylandMessage},
};

const RECORD_TYPE_MESSAGE: u32 = 0;
const RECORD_TYPE_FD_UPDATE: u32 = 1;

/// Primary LibAFL input model: parsed WLIR header + message vector in memory.
/// `.wlir` bytes remain a persistence/interop format via `to_wlir_bytes`.
#[derive(Debug, Clone)]
pub struct WlirInput {
    pub header: IrFileHeader,
    pub messages: Vec<WaylandMessage>,
}

impl WlirInput {
    pub fn from_reader(mut reader: IrReader) -> io::Result<Self> {
        let header = reader.header;
        let messages = reader.read_all()?;
        Ok(Self { header, messages })
    }

    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let reader = IrReader::from_bytes(bytes.to_vec())?;
        Self::from_reader(reader)
    }

    pub fn to_wlir_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_header(&mut out, &self.header);

        for message in &self.messages {
            let message_record_size = std::mem::size_of::<IrRecordHeader>()
                + std::mem::size_of::<IrMessageRecord>()
                + message.wire_data.len()
                + message.fds.len() * std::mem::size_of::<IrFdInfo>()
                + message.fds.iter().map(|fd| fd.content.len()).sum::<usize>();

            push_u32(&mut out, RECORD_TYPE_MESSAGE);
            push_u32(&mut out, message_record_size as u32);

            let msg_record = IrMessageRecord {
                timestamp_us: message.timestamp_us,
                object_id: message.object_id,
                opcode: message.opcode,
                direction: direction_to_u8(message.direction),
                fd_count: message.fds.len() as u8,
                size: message.wire_data.len() as u32,
                instance_id: message.instance_id,
            };
            push_message_record(&mut out, &msg_record);
            out.extend_from_slice(&message.wire_data);

            for fd in &message.fds {
                let fd_info = IrFdInfo {
                    fd_num: fd.fd_num,
                    fd_type: fd.fd_type as u32,
                    content_size: fd.content.len() as u64,
                    flags: fd_flags(fd),
                    format_hint: fd.format_hint,
                };
                push_fd_info(&mut out, &fd_info);
            }
            for fd in &message.fds {
                out.extend_from_slice(&fd.content);
            }

            for update in &message.fd_updates {
                let record_size = (std::mem::size_of::<IrRecordHeader>()
                    + std::mem::size_of::<IrFdUpdateRecord>())
                    as u32;
                push_u32(&mut out, RECORD_TYPE_FD_UPDATE);
                push_u32(&mut out, record_size);

                let update_record = IrFdUpdateRecord {
                    object_id: update.object_id,
                    new_size: update.new_size,
                    content_size: update.content.len() as u64,
                    flags: 0,
                    reserved: 0,
                };
                push_fd_update_record(&mut out, &update_record);
                out.extend_from_slice(&update.content);
            }
        }

        out
    }
}

impl Hash for WlirInput {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.header.start_time_us.hash(state);
        self.to_wlir_bytes().hash(state);
    }
}

impl Serialize for WlirInput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_wlir_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for WlirInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        WlirInput::from_bytes(&bytes).map_err(de::Error::custom)
    }
}

impl Input for WlirInput {}

impl HasLen for WlirInput {
    fn len(&self) -> usize {
        self.messages.len()
    }
}

impl HasTargetBytes for WlirInput {
    fn target_bytes(&self) -> OwnedSlice<'_, u8> {
        OwnedSlice::from(self.to_wlir_bytes())
    }
}

fn direction_to_u8(direction: Direction) -> u8 {
    match direction {
        Direction::ClientToServer => 0,
        Direction::ServerToClient => 1,
    }
}

fn fd_flags(fd: &FdRecord) -> u32 {
    let mut flags = 0;
    if fd.seekable {
        flags |= 0x1;
    }
    if fd.truncated {
        flags |= 0x2;
    }
    flags
}

fn push_header(out: &mut Vec<u8>, header: &IrFileHeader) {
    push_u32(out, header.magic);
    push_u32(out, header.version);
    push_u64(out, header.start_time_us);
    push_u32(out, header.flags);
    push_u32(out, header.reserved);
}

fn push_message_record(out: &mut Vec<u8>, record: &IrMessageRecord) {
    push_u64(out, record.timestamp_us);
    push_u32(out, record.object_id);
    push_u16(out, record.opcode);
    out.push(record.direction);
    out.push(record.fd_count);
    push_u32(out, record.size);
    push_u32(out, record.instance_id);
}

fn push_fd_info(out: &mut Vec<u8>, info: &IrFdInfo) {
    push_u32(out, info.fd_num);
    push_u32(out, info.fd_type);
    push_u64(out, info.content_size);
    push_u32(out, info.flags);
    push_u32(out, info.format_hint);
}

fn push_fd_update_record(out: &mut Vec<u8>, update: &IrFdUpdateRecord) {
    push_u32(out, update.object_id);
    push_u32(out, update.new_size);
    push_u64(out, update.content_size);
    push_u32(out, update.flags);
    push_u32(out, update.reserved);
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use wl_repeater::{
        ir::IrFileHeader,
        message::{Direction, FdRecord, FdType, FdUpdateRecord},
    };

    fn sample_header() -> IrFileHeader {
        IrFileHeader {
            magic: 0x574C_4952,
            version: 2,
            start_time_us: 123,
            flags: 1,
            reserved: 0,
        }
    }

    fn sample_message() -> WaylandMessage {
        WaylandMessage {
            timestamp_us: 456,
            instance_id: 9,
            object_id: 7,
            opcode: 3,
            direction: Direction::ClientToServer,
            wire_data: vec![7, 0, 0, 0, 3, 0, 16, 0, 1, 2, 3, 4, 5, 6, 7, 8],
            fds: vec![FdRecord {
                fd_num: 11,
                fd_type: FdType::Shm,
                seekable: true,
                truncated: false,
                format_hint: 22,
                original_size: 2,
                content: vec![0xAA, 0xBB],
            }],
            fd_updates: vec![FdUpdateRecord {
                object_id: 11,
                new_size: 128,
                content: vec![0x01, 0x02, 0x03],
            }],
            decoded_args: Vec::new(),
        }
    }

    #[test]
    fn len_returns_message_count() {
        let input = WlirInput {
            header: sample_header(),
            messages: vec![sample_message(), sample_message()],
        };

        assert_eq!(input.len(), 2);
    }

    #[test]
    fn target_bytes_start_with_wlir_magic() {
        let input = WlirInput {
            header: sample_header(),
            messages: vec![sample_message()],
        };

        let bytes = input.to_wlir_bytes();
        assert_eq!(&bytes[0..4], &0x574C_4952u32.to_le_bytes());
    }

    #[test]
    fn round_trip_bytes_preserve_records() {
        let original = WlirInput {
            header: sample_header(),
            messages: vec![sample_message()],
        };

        let bytes = original.to_wlir_bytes();
        let reparsed = WlirInput::from_bytes(&bytes).expect("bytes should parse");
        let reserialized = reparsed.to_wlir_bytes();

        assert_eq!(original.header.magic, reparsed.header.magic);
        assert_eq!(original.header.version, reparsed.header.version);
        assert_eq!(original.header.start_time_us, reparsed.header.start_time_us);
        assert_eq!(original.messages.len(), reparsed.messages.len());
        assert_eq!(bytes, reserialized);

        let msg = &reparsed.messages[0];
        assert_eq!(msg.fds.len(), 1);
        assert_eq!(msg.fds[0].fd_num, 11);
        assert_eq!(msg.fds[0].format_hint, 22);
        assert_eq!(msg.fds[0].content, vec![0xAA, 0xBB]);
        assert_eq!(msg.fd_updates.len(), 1);
        assert_eq!(msg.fd_updates[0].object_id, 11);
        assert_eq!(msg.fd_updates[0].new_size, 128);
        assert_eq!(msg.fd_updates[0].content, vec![0x01, 0x02, 0x03]);
    }
}
