// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::ops::ControlFlow;

/// Iterator with a lazy fallible initialiser
///
/// It is a common pattern that instantiating an effectful iterator is fallible,
/// while traversing it is fallible, too. This yields unwieldy signatures like:
///
/// ```no_run
/// fn my_iterator() -> Result<impl Iterator<Item = Result<T, F>>, E>
/// ```
///
/// Often, however, we can unify the error types (`E` and `F` above), which
/// allows for the more pleasant pattern that constructing the iterator is
/// infallible, but an initialiser error is returned upon the first call to
/// `next()`. Ie.:
///
/// ```no_run
/// fn my_iterator() -> impl Iterator<Item = Result<T, E>>
/// ```
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct Iter<E, F, I, G> {
    init: Option<F>,
    iter: Option<Result<I, E>>,
    next: G,
}

impl<E, F, I, G> Iter<E, F, I, G> {
    pub fn new(init: F, next: G) -> Self {
        Self {
            init: Some(init),
            iter: None,
            next,
        }
    }
}

impl<E, F, I, G, T, U> Iterator for Iter<E, F, I, G>
where
    F: FnOnce() -> Result<I, E>,
    I: Iterator<Item = Result<T, E>>,
    G: FnMut(Result<T, E>) -> Option<Result<U, E>>,
{
    type Item = Result<U, E>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.iter.take() {
            None => {
                let init = self.init.take()?;
                self.iter = Some(init());
                self.next()
            },
            Some(Err(e)) => Some(Err(e)),
            Some(Ok(mut iter)) => {
                let item = iter.next()?;
                let next = (self.next)(item);
                self.iter = Some(Ok(iter));
                next
            },
        }
    }
}

impl<E, F, I, G, T, U> DoubleEndedIterator for Iter<E, F, I, G>
where
    F: FnOnce() -> Result<I, E>,
    I: Iterator<Item = Result<T, E>> + DoubleEndedIterator,
    G: FnMut(Result<T, E>) -> Option<Result<U, E>>,
{
    fn next_back(&mut self) -> Option<Self::Item> {
        match self.iter.take() {
            None => {
                let init = self.init.take()?;
                self.iter = Some(init());
                self.next_back()
            },
            Some(Err(e)) => Some(Err(e)),
            Some(Ok(mut iter)) => {
                let item = iter.next_back()?;
                let next = (self.next)(item);
                self.iter = Some(Ok(iter));
                next
            },
        }
    }
}

pub(crate) trait IteratorExt {
    fn try_find_map<F, T, E>(&mut self, mut f: F) -> crate::Result<Option<T>>
    where
        Self: Iterator + Sized,
        F: FnMut(Self::Item) -> Result<Option<T>, E>,
        E: Into<crate::Error>,
    {
        let x = self.try_fold((), |(), i| match f(i) {
            Err(e) => ControlFlow::Break(Err(e.into())),
            Ok(v) if v.is_some() => ControlFlow::Break(Ok(v)),
            Ok(_) => ControlFlow::Continue(()),
        });
        match x {
            ControlFlow::Continue(()) => Ok(None),
            ControlFlow::Break(v) => v,
        }
    }
}

impl<T: Iterator> IteratorExt for T {}
