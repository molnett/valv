use std::time::{Duration, SystemTime};
use std::sync::Mutex;

pub struct MockClock {
    current_time: Mutex<SystemTime>,
}

impl MockClock {
    pub fn new(initial_time: SystemTime) -> Self {
        MockClock {
            current_time: Mutex::new(initial_time),
        }
    }

    fn now(&self) -> SystemTime {
        *self.current_time.lock().unwrap()
    }

    fn advance(&self, duration: Duration) {
        let mut current_time = self.current_time.lock().unwrap();
        *current_time += duration;
    }
}

pub trait Clock: Send + Sync {
    fn now(&self) -> SystemTime;
}

impl Clock for MockClock {
    fn now(&self) -> SystemTime {
        self.now()
    }
}

impl Clock for SystemTime {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    #[test]
    fn test_mock_clock_new() {
        let initial_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let clock = MockClock::new(initial_time);
        assert_eq!(clock.now(), initial_time);
    }

    #[test]
    fn test_mock_clock_advance() {
        let initial_time = SystemTime::UNIX_EPOCH;
        let clock = MockClock::new(initial_time);
        
        clock.advance(Duration::from_secs(60));
        assert_eq!(clock.now(), initial_time + Duration::from_secs(60));

        clock.advance(Duration::from_secs(30));
        assert_eq!(clock.now(), initial_time + Duration::from_secs(90));
    }

    #[test]
    fn test_mock_clock_multiple_advances() {
        let initial_time = SystemTime::UNIX_EPOCH;
        let clock = MockClock::new(initial_time);
        
        for i in 1..=5 {
            clock.advance(Duration::from_secs(10));
            assert_eq!(clock.now(), initial_time + Duration::from_secs(i * 10));
        }
    }

    #[test]
    fn test_mock_clock_trait_implementation() {
        let initial_time = SystemTime::UNIX_EPOCH + Duration::from_secs(500);
        let clock: Box<dyn Clock> = Box::new(MockClock::new(initial_time));
        
        assert_eq!(clock.now(), initial_time);
    }

    #[test]
    fn test_system_time_clock_trait_implementation() {
        let clock: Box<dyn Clock> = Box::new(SystemTime::UNIX_EPOCH);
        
        // This test is non-deterministic, but we can check if the time is recent
        let now = clock.now();
        let elapsed = now.duration_since(SystemTime::UNIX_EPOCH).unwrap();
        assert!(elapsed.as_secs() > 0);
    }
}