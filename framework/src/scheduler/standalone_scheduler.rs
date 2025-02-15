use super::{Executable, Scheduler};
use crate::common::*;
use crate::utils;
use std::default::Default;
use std::sync::mpsc::{sync_channel, Receiver, RecvError, SyncSender};
use std::sync::Arc;
use std::thread;

/// Used to keep stats about each pipeline and eventually grant tokens, etc.
struct Runnable {
    pub task: Box<dyn Executable>,
    pub cycles: u64,
    pub last_run: u64,
}

impl Runnable {
    pub fn from_task<T: Executable + 'static>(task: T) -> Runnable {
        Runnable {
            task: box task,
            cycles: 0,
            last_run: utils::rdtsc_unsafe(),
        }
    }
    pub fn from_boxed_task(task: Box<dyn Executable>) -> Runnable {
        Runnable {
            task,
            cycles: 0,
            last_run: utils::rdtsc_unsafe(),
        }
    }
}

/// A very simple round-robin scheduler. This should really be more of a DRR scheduler.
pub struct StandaloneScheduler {
    /// The set of runnable items. Note we currently don't have a blocked queue.
    run_q: Vec<Runnable>,
    /// Next task to run.
    next_task: usize,
    /// Channel to communicate and synchronize with scheduler.
    sched_channel: Receiver<SchedulerCommand>,
    /// Signal scheduler should continue executing tasks.
    execute_loop: bool,
    /// Signal scheduler should shutdown.
    shutdown: bool,
}

/// Messages that can be sent on the scheduler channel to add or remove tasks.
pub enum SchedulerCommand {
    /// Add command.
    Add(Box<dyn Executable + Send>),
    /// Run command.
    Run(Arc<dyn Fn(&mut StandaloneScheduler) + Send + Sync>),
    /// Execute command.
    Execute,
    /// Shutdown command.
    Shutdown,
    /// Handshake command.
    Handshake(SyncSender<bool>),
}

const DEFAULT_Q_SIZE: usize = 256;

impl Default for StandaloneScheduler {
    /// Initialize a default StandaloneScheduler.
    fn default() -> StandaloneScheduler {
        StandaloneScheduler::new()
    }
}

impl Scheduler for StandaloneScheduler {
    /// Add a task to the current scheduler.
    fn add_task<T: Executable + 'static>(&mut self, task: T) -> Result<usize> {
        self.run_q.push(Runnable::from_task(task));
        Ok(self.run_q.len())
    }
}

impl StandaloneScheduler {
    /// Initialize a StandaloneScheduler.
    pub fn new() -> StandaloneScheduler {
        let (_, receiver) = sync_channel(0);
        StandaloneScheduler::new_with_channel(receiver)
    }

    /// Initialize a StandaloneScheduler with channel.
    pub fn new_with_channel(channel: Receiver<SchedulerCommand>) -> StandaloneScheduler {
        StandaloneScheduler::new_with_channel_and_capacity(channel, DEFAULT_Q_SIZE)
    }

    /// Initialize a StandaloneScheduler with channel and capacity.
    pub fn new_with_channel_and_capacity(channel: Receiver<SchedulerCommand>, capacity: usize) -> StandaloneScheduler {
        StandaloneScheduler {
            run_q: Vec::with_capacity(capacity),
            next_task: 0,
            sched_channel: channel,
            execute_loop: false,
            shutdown: true,
        }
    }

    /// Handle one request and then exit.
    fn handle_request(&mut self, request: SchedulerCommand) {
        match request {
            SchedulerCommand::Add(ex) => self.run_q.push(Runnable::from_boxed_task(ex)),
            SchedulerCommand::Run(f) => f(self),
            SchedulerCommand::Execute => self.execute_loop(),
            SchedulerCommand::Shutdown => {
                self.execute_loop = false;
                self.shutdown = true;
            }
            SchedulerCommand::Handshake(chan) => {
                chan.send(true).unwrap(); // Inform context about reaching barrier.
                thread::park();
            }
        }
    }

    /// Handle the requests and then exit.
    pub fn handle_requests(&mut self) {
        self.shutdown = false;
        // Note this rather bizarre structure here to get shutting down hooked in.
        while let Ok(cmd) = {
            if self.shutdown {
                Err(RecvError)
            } else {
                self.sched_channel.recv()
            }
        } {
            self.handle_request(cmd)
        }
        println!(
            "Scheduler exiting {}",
            thread::current().name().unwrap_or("unknown-name")
        );
    }

    /// Run the scheduling.
    #[inline]
    fn execute_internal(&mut self, begin: u64) -> u64 {
        let time = {
            let task = &mut (&mut self.run_q[self.next_task]);
            task.task.execute();
            let end = utils::rdtsc_unsafe();
            task.cycles += end - begin;
            task.last_run = end;
            end
        };
        let len = self.run_q.len();
        let next = self.next_task + 1;
        if next == len {
            self.next_task = 0;
            if let Ok(cmd) = self.sched_channel.try_recv() {
                self.handle_request(cmd);
            }
        } else {
            self.next_task = next;
        };
        time
    }

    /// Run the scheduling loop.
    pub fn execute_loop(&mut self) {
        self.execute_loop = true;
        let mut begin_time = utils::rdtsc_unsafe();
        if !self.run_q.is_empty() {
            while self.execute_loop {
                begin_time = self.execute_internal(begin_time)
            }
        }
    }

    /// Run the scheduling once.
    pub fn execute_one(&mut self) {
        if !self.run_q.is_empty() {
            self.execute_internal(utils::rdtsc_unsafe());
        }
    }
}
