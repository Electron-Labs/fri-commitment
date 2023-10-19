use ark_ff::PrimeField;
use merlin::Transcript;

pub trait TranscriptProtocol<F: PrimeField> {
    fn observe_element(&mut self, label: &'static [u8], elem: &F);
    fn observe_elements(&mut self, label: &'static [u8], elems: &Vec<F>);
    fn get_challenge(&mut self, label: &'static [u8]) -> F;
    fn get_challenge_indices(&mut self, label: &'static [u8], n: usize) -> Vec<u32>;
}

impl<F: PrimeField> TranscriptProtocol<F> for Transcript {
    fn observe_element(&mut self, label: &'static [u8], elem: &F) {
        let mut buffer = vec![];
        elem.serialize_uncompressed(&mut buffer).expect("Serialization Failed");
        self.append_message(label, &buffer);
    }

    fn observe_elements(&mut self, label: &'static [u8], elems: &Vec<F>) {
        let mut buffer = vec![];
        for e in elems {
            e.serialize_uncompressed(&mut buffer).expect("Serialization Failed");
        }
        self.append_message(label, &buffer);
    }

    fn get_challenge(&mut self, label: &'static [u8]) -> F {
        let elem_byte_size = (F::MODULUS_BIT_SIZE/8) as usize;
        let mut buf = vec![0; elem_byte_size];
        self.challenge_bytes(label, &mut buf);
        F::from_le_bytes_mod_order(&buf)
    }

    fn get_challenge_indices(&mut self, label: &'static [u8], n: usize) -> Vec<u32> {
        let mut buf = vec![0; n * 4];
        self.challenge_bytes(label, &mut buf);
        let mut challenge_indices = vec![];
        for i in 0..n {
            challenge_indices.push(u32::from_le_bytes([buf[i*4], buf[i*4+1], buf[i*4+2], buf[i*4+3]]));
        }
        challenge_indices
    }
}

#[cfg(test)]
mod tests {
    use crate::fields::goldilocks_field::Fq;
    use super::TranscriptProtocol;
    use merlin::Transcript;

    #[test]
    fn test_fiat_shamir() {
        let mut transcript_p = Transcript::new(b"new");
        let elements = vec![Fq::from(1), Fq::from(2), Fq::from(64)];
        transcript_p.observe_element(b"one elem", &elements[0]);
        transcript_p.observe_elements(b"multiple elems", &elements);

        let c1_p: Fq = transcript_p.get_challenge(b"first challenge");
        let c2_p = <Transcript as TranscriptProtocol<Fq>>::get_challenge_indices(&mut transcript_p, b"multiple challenges", 2);

        let mut transcript_v = Transcript::new(b"new");
        // let elements = vec![Fq::from(1), Fq::from(2), Fq::ZERO, Fq::from(64)];
        transcript_v.observe_element(b"one elem", &elements[0]);
        transcript_v.observe_elements(b"multiple elems", &elements);

        let c1_v: Fq = transcript_v.get_challenge(b"first challenge");
        let c2_v = <Transcript as TranscriptProtocol<Fq>>::get_challenge_indices(&mut transcript_v, b"multiple challenges", 2);

        assert_eq!(c1_p, c1_v);
        assert_eq!(c2_p, c2_v);
    }
}
