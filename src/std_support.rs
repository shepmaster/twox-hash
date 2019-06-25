pub mod sixty_four {
    use crate::XxHash;
    use core::hash::BuildHasher;
    use rand::{self, Rng};

    #[derive(Clone)]
    /// Constructs a randomized seed and reuses it for multiple hasher instances.
    pub struct RandomXxHashBuilder(u64);

    impl RandomXxHashBuilder {
        fn new() -> RandomXxHashBuilder {
            RandomXxHashBuilder(rand::thread_rng().gen())
        }
    }

    impl Default for RandomXxHashBuilder {
        fn default() -> RandomXxHashBuilder {
            RandomXxHashBuilder::new()
        }
    }

    impl BuildHasher for RandomXxHashBuilder {
        type Hasher = XxHash;

        fn build_hasher(&self) -> XxHash {
            XxHash::with_seed(self.0)
        }
    }
}

pub mod thirty_two {
    use crate::thirty_two::XxHash;
    use core::hash::BuildHasher;
    use rand::{self, Rng};

    #[derive(Clone)]
    /// Constructs a randomized seed and reuses it for multiple hasher instances. See the usage warning on `XxHash32`.
    pub struct RandomXxHashBuilder(u32);

    impl RandomXxHashBuilder {
        fn new() -> RandomXxHashBuilder {
            RandomXxHashBuilder(rand::thread_rng().gen())
        }
    }

    impl Default for RandomXxHashBuilder {
        fn default() -> RandomXxHashBuilder {
            RandomXxHashBuilder::new()
        }
    }

    impl BuildHasher for RandomXxHashBuilder {
        type Hasher = XxHash;

        fn build_hasher(&self) -> XxHash {
            XxHash::with_seed(self.0)
        }
    }
}
