use num_traits::FromPrimitive;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Num<P, E>
where
    P: From<E>,
{
    Assigned(E),
    Unassigned(P),
}

struct Primitive<P>(P);

impl<P> Primitive<P> {
    pub fn into_inner(self) -> P {
        self.0
    }
}

impl<P, E> From<Num<P, E>> for Primitive<P>
where
    P: From<E>,
{
    fn from(value: Num<P, E>) -> Self {
        match value {
            Num::Assigned(e) => Primitive(e.into()),
            Num::Unassigned(p) => Primitive(p),
        }
    }
}

impl<E> From<Num<u8, E>> for u8
where
    u8: From<E>,
{
    fn from(value: Num<u8, E>) -> Self {
        Into::<Primitive<u8>>::into(value).into_inner()
    }
}

impl<E> From<Num<u16, E>> for u16
where
    u16: From<E>,
{
    fn from(value: Num<u16, E>) -> Self {
        Into::<Primitive<u16>>::into(value).into_inner()
    }
}

impl<P, E> From<P> for Num<P, E>
where
    E: FromPrimitive,
    P: Copy + From<E> + Into<u64>,
{
    fn from(value: P) -> Self {
        match E::from_u64(value.into()) {
            Some(n) => Num::Assigned(n.into()),
            None => Num::Unassigned(value),
        }
    }
}
