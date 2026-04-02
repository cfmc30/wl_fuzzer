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
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _new_corpus_id: Option<libafl::corpus::CorpusId>,
    ) -> Result<(), libafl::Error> {
        Ok(())
    }
}
