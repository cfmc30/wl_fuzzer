use std::borrow::Cow;

use libafl::{
    Error,
    corpus::CorpusId,
    inputs::{BytesInput, HasMutatorBytes},
    mutators::{MutationResult, Mutator},
    state::HasRand,
};
use libafl_bolts::{
    Named,
    rands::{Rand, StdRand},
};

use wl_repeater::ir::IrReader;

use crate::parse_input_as_wlir;

pub struct IRMutator;

impl Named for IRMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("IRMutator");
        &NAME
    }
}

impl<S> Mutator<BytesInput, S> for IRMutator
where
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut BytesInput,
    ) -> Result<libafl::mutators::MutationResult, libafl::Error> {
        match parse_input_as_wlir(input.mutator_bytes()) {
            Ok(mut result) => {
                loop {
                    match result.next_message() {
                        Ok(None) => break,
                        Ok(Some(msg)) => {
                            // mutate it
                        }
                        Err(err) => {
                            return Err(libafl::Error::invalid_corpus(format!(
                                "Invalid input, trace parce error, {}",
                                err
                            )));
                        }
                    }
                }
                Ok(libafl::mutators::MutationResult::Mutated)
            }
            Err(err) => Err(libafl::Error::invalid_corpus(format!(
                "Invalid input, trace parce error, {}",
                err
            ))),
        }
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _new_corpus_id: Option<libafl::corpus::CorpusId>,
    ) -> Result<(), libafl::Error> {
        Ok(())
    }
}
