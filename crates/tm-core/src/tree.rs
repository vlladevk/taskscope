//! The “who started whom” tree and subtree totals.

use crate::sampler::ProcStat;
use std::collections::HashMap;

pub struct Tree {
    pub parent: Vec<Option<usize>>,
    pub children: Vec<Vec<usize>>,
    pub roots: Vec<usize>,
}

impl Tree {
    /// Builds the tree by PPID. A parent is accepted only if it was created before the child —
    /// otherwise the PPID points to a process that already died and whose PID someone else took.
    pub fn build(procs: &[ProcStat]) -> Self {
        let by_pid: HashMap<u32, usize> = procs.iter().enumerate().map(|(i, p)| (p.pid, i)).collect();
        let mut parent = vec![None; procs.len()];
        let mut children = vec![Vec::new(); procs.len()];
        let mut roots = Vec::new();
        for (i, p) in procs.iter().enumerate() {
            let par = if p.pid == 0 || p.pid == p.ppid {
                None
            } else {
                by_pid.get(&p.ppid).copied().filter(|&j| {
                    let q = &procs[j];
                    q.pid != 0 && q.create_time <= p.create_time
                })
            };
            parent[i] = par;
            match par {
                Some(j) => children[j].push(i),
                None => roots.push(i),
            }
        }
        Self { parent, children, roots }
    }

    /// Indices of all descendants (without the node itself).
    pub fn descendants(&self, i: usize) -> Vec<usize> {
        let mut out = Vec::new();
        let mut stack = self.children[i].clone();
        while let Some(j) = stack.pop() {
            out.push(j);
            stack.extend_from_slice(&self.children[j]);
        }
        out
    }

    /// The chain of ancestors from the root to the node (without the node itself).
    pub fn ancestors(&self, i: usize) -> Vec<usize> {
        let mut out = Vec::new();
        let mut cur = self.parent[i];
        while let Some(j) = cur {
            if out.contains(&j) {
                break; // protection against cycles in broken data
            }
            out.push(j);
            cur = self.parent[j];
        }
        out.reverse();
        out
    }

    /// Subtree totals (node + all descendants) for an arbitrary metric.
    pub fn inclusive<F: Fn(usize) -> f64>(&self, n: usize, f: F) -> Vec<f64> {
        self.inclusive_if(n, f, |_, _| true)
    }

    /// Like `inclusive`, but a child’s value is added to its parent only if `joins(parent, child)`.
    /// That is how the “by app” total is computed: programs started from Explorer are not in its total.
    pub fn inclusive_if<F: Fn(usize) -> f64, J: Fn(usize, usize) -> bool>(&self, n: usize, f: F, joins: J) -> Vec<f64> {
        let mut acc: Vec<f64> = (0..n).map(&f).collect();
        // walk in reverse depth order: leaves first
        let mut order = Vec::with_capacity(n);
        let mut stack: Vec<usize> = self.roots.clone();
        while let Some(i) = stack.pop() {
            order.push(i);
            stack.extend_from_slice(&self.children[i]);
        }
        for &i in order.iter().rev() {
            if let Some(p) = self.parent[i] {
                if joins(p, i) {
                    acc[p] += acc[i];
                }
            }
        }
        acc
    }
}
