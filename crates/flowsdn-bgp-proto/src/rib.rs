//! Separate local origin and received observation stores. There is deliberately
//! no operation that promotes a received route into local origin state.
use crate::update::{Prefix,Summary};
use std::{collections::BTreeSet,sync::Arc};
#[derive(Clone,Debug)]
pub struct PathHandle {issuer:Arc<()>,prefix:Prefix,incarnation:Arc<()>}
#[derive(Debug,Default)]
pub struct LocalRib {issuer:Arc<()>,prefixes:BTreeSet<Prefix>,handles:std::collections::BTreeMap<Prefix,Arc<()>>}
impl LocalRib {
    pub fn advertise(&mut self,prefix:Prefix)->PathHandle {self.prefixes.insert(prefix);let incarnation=self.handles.entry(prefix).or_default().clone();PathHandle {issuer:self.issuer.clone(),prefix,incarnation}}
    pub fn withdraw(&mut self,handle:&PathHandle)->bool {if !Arc::ptr_eq(&self.issuer,&handle.issuer)||!self.handles.get(&handle.prefix).is_some_and(|active|Arc::ptr_eq(active,&handle.incarnation)){return false;}self.handles.remove(&handle.prefix);self.prefixes.remove(&handle.prefix)}
    pub fn prefixes(&self)->&BTreeSet<Prefix>{&self.prefixes}
}
#[derive(Clone,Copy,Debug,Default,Eq,PartialEq)]
pub struct Counters {pub announcements:u64,pub withdrawals:u64,pub omitted:u64}
/// One instance per peer; the cap applies separately to each address family.
/// Counters are message observations, not an exact live cardinality estimate
/// after overflow: exact unique counts would themselves require unbounded RAM.
#[derive(Debug)]
pub struct ObservedRib {cap:usize,v4:BTreeSet<Prefix>,v6:BTreeSet<Prefix>,counters:Counters,overflow_reported:bool}
impl ObservedRib {
    pub fn new(cap:usize)->Self {Self {cap,v4:BTreeSet::new(),v6:BTreeSet::new(),counters:Counters::default(),overflow_reported:false}}
    pub fn counters(&self)->Counters{self.counters}
    pub fn prefixes(&self,ipv6:bool)->&BTreeSet<Prefix>{if ipv6{&self.v6}else{&self.v4}}
    /// Returns true exactly on the first storage overflow, for one log per peer.
    pub fn observe(&mut self,update:&Summary)->bool {
        for prefix in update.withdrawn.iter().chain(&update.mp_withdrawn) {
            self.counters.withdrawals=self.counters.withdrawals.saturating_add(1);
            if prefix.address().is_ipv6(){self.v6.remove(prefix);}else{self.v4.remove(prefix);}
        }
        let mut overflow=false;
        for prefix in update.announced.iter().chain(&update.mp_announced) {
            self.counters.announcements=self.counters.announcements.saturating_add(1);
            let store=if prefix.address().is_ipv6(){&mut self.v6}else{&mut self.v4};
            if store.contains(prefix){continue;}
            if store.len()<self.cap{store.insert(*prefix);}else{self.counters.omitted=self.counters.omitted.saturating_add(1);overflow=true;}
        }
        let report=overflow&&!self.overflow_reported;self.overflow_reported|=overflow;report
    }
}
