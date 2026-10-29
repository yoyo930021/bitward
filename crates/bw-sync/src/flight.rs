//! sync 觸發的單飛去重（契约 §1.1「targeted pull 縮小衝突窗口」的執行側）。
//!
//! 場景：notifications 事件一秒內到幾十條（他台裝置批次改 30 筆），每條都叫
//! daemon「去 sync」；不合併就會打爆伺服器、後到的 pull 還會踩掉前一個。
//! `SingleFlight` 保證同一時刻最多一條 sync 在跑，並提供去重視窗（預設
//! 250ms coalesce）：視窗內的 trigger 全部掛在同一班機上。
//!
//! 語意（final consistency）：
//! - `trigger()` 回一個 [`Run`] future。`Run.await` 完成時，「一次在你
//!   trigger 之後**開始**的 sync 已經結束」——要嘛你就是該 sync 的執行者
//!   （[`RunOutcome::Execute`]，跑完必須呼叫 [`SingleFlight::finish`]，成功
//!   失敗都要），要嘛別人那班已涵蓋你（[`RunOutcome::Covered`]）。
//! - sync 進行中才到的 trigger 不被當前班機涵蓋（那班可能已讀過伺服器、
//!   看不到這次變更），`finish()` 時自動升下一班並把 `Execute` 交棒給最早
//!   的尾端等待者——尾端事件不會餓死。
//! - 無 busy-poll：等待全憑 `tokio::time::Sleep`（重視窗）與
//!   `tokio::sync::oneshot`（交棒），沒有輪詢迴圈。
//!
//! 實作是 `std::sync::Mutex` + 世代計數器（契約寫 "tokio Mutex 或等價"；這裡
//! 臨界區全同步、不含 await，標準 Mutex 等價且免執行緒交接）。狀態藏在 `Arc`，
//! `SingleFlight` 可複製（同一閘門）、可丟。
//!
//! 紀律：拿到 `Execute` 的 Run 作廢前要先 `finish()`。若 Run 被直接 drop
//! （panic／取消），該班視為**未執行**：不推進 `completed_generation`，
//! 尾端等待者改掛下一班——保守但永不卡死。

use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::sync::oneshot;
use tokio::time::Sleep;

/// 契約建議的重視窗：250ms。
pub const DEFAULT_COALESCE: Duration = Duration::from_millis(250);

/// `Run.await` 的結局。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunOutcome {
    /// 你是這班機器的執行者：現在去跑 sync，跑完呼叫 [`SingleFlight::finish`]。
    Execute,
    /// 有一班在你 trigger 之後開始的 sync 已完成；不用再做。
    Covered,
}

/// 等待中的班機被拆掉（罕見：整個閘門連同執行者消失）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("sync flight was cancelled")]
pub struct RunCancelled;

struct Flight {
    /// 執行者的世代；辨認「這班是我」。
    executor_gen: u64,
    /// 執行者已通過重視窗、正在（或即將）跑 sync。
    claimed: bool,
    /// claim 時的 `next_gen`：世代 < 此值的 trigger 都被這班涵蓋。
    claim_gen: u64,
}

struct Waiter {
    tx: oneshot::Sender<RunOutcome>,
    /// true = 註冊時當前班機已 claim，需要**下一班**才涵蓋。
    needs_next: bool,
}

struct State {
    next_gen: u64,
    completed_gen: u64,
    flight: Option<Flight>,
    /// generation → waiter；BTreeMap 保證升序，升班拿最小世代。
    waiters: BTreeMap<u64, Waiter>,
}

struct Inner {
    state: Mutex<State>,
    /// 已交付的 `Execute` 數（性質測試用；執行者跑完就該有一次 finish）。
    executes: AtomicUsize,
}

/// 單飛 trigger 閘門。`Clone` 共享同一個閘門（同一 `Arc`）。
#[derive(Clone)]
pub struct SingleFlight {
    inner: Arc<Inner>,
    coalesce: Duration,
}

impl Default for SingleFlight {
    fn default() -> Self {
        Self::new()
    }
}

impl SingleFlight {
    /// 以預設 250ms 重視窗建立。
    #[must_use]
    pub fn new() -> Self {
        Self::with_coalesce(DEFAULT_COALESCE)
    }

    /// 自訂重視窗（測試用短窗；`Duration::ZERO` 表示不等待）。
    #[must_use]
    pub fn with_coalesce(coalesce: Duration) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    next_gen: 1,
                    completed_gen: 0,
                    flight: None,
                    waiters: std::collections::BTreeMap::new(),
                }),
                executes: AtomicUsize::new(0),
            }),
            coalesce,
        }
    }

    /// 登記一次「請去 sync」。N 個併發呼叫 → 1 個拿到 `Execute`、其餘
    /// `Covered`（若全落在重視窗/同一班在飛期間內）。
    ///
    /// `async` 是介面穩定性（契約凍結 `pub async fn trigger`）；註冊本身同步。
    // Contract freezes the async signature; registration is synchronous today.
    #[allow(clippy::unused_async)]
    pub async fn trigger(&self) -> Run {
        let mut st = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        let generation = st.next_gen;
        st.next_gen += 1;
        match &mut st.flight {
            None => {
                st.flight = Some(Flight {
                    executor_gen: generation,
                    claimed: false,
                    claim_gen: 0,
                });
                drop(st);
                Run {
                    generation,
                    inner: Arc::clone(&self.inner),
                    role: RunRole::Coalescing(Box::pin(tokio::time::sleep(self.coalesce))),
                }
            }
            Some(f) => {
                let needs_next = f.claimed;
                let (tx, rx) = oneshot::channel();
                st.waiters.insert(generation, Waiter { tx, needs_next });
                Run {
                    generation,
                    inner: Arc::clone(&self.inner),
                    role: RunRole::Waiting(rx),
                }
            }
        }
    }

    /// 已發出的最後世代編號（0 = 還沒有人 trigger）。
    #[must_use]
    pub fn generation(&self) -> u64 {
        let st = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        st.next_gen - 1
    }

    /// 已被「完成的 sync」涵蓋的最高世代。等待者醒來後可用它驗證最終一致性：
    /// `completed_generation() >= 自己的 Run::generation()`。
    #[must_use]
    pub fn completed_generation(&self) -> u64 {
        let st = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        st.completed_gen
    }

    /// 交付過幾次 `Execute`（觀測用；等於底層 sync 排程次數）。
    #[must_use]
    pub fn execution_count(&self) -> usize {
        self.inner.executes.load(Ordering::SeqCst)
    }

    /// 執行者回報這班 sync 結束（不管成敗），並交棒給尾端等待者。
    /// 必須與 [`RunOutcome::Execute`] 配對；沒有在飛班機時是 no-op。
    pub fn finish(&self) {
        complete(&self.inner, None, true);
    }
}

enum RunRole {
    /// 重視窗倒數中；醒來後嘗試 claim 班機。
    Coalescing(Pin<Box<Sleep>>),
    /// 掛在交棒通道上。
    Waiting(oneshot::Receiver<RunOutcome>),
    /// 已回傳結局。
    Done,
}

/// `SingleFlight::trigger` 回傳的等待未來。`.await` 到
/// `Ok(RunOutcome)`；只有班機被拆掉才 `Err(RunCancelled)`。
///
/// 實作 `Future` 於 `Run` 與 `&mut Run`（`Run: Unpin`），所以 `(&mut run).await`
/// 之後還留著 `run` 可查 [`Run::generation`]。
#[must_use = "Run must be awaited so the flight can hand over"]
pub struct Run {
    generation: u64,
    inner: Arc<Inner>,
    role: RunRole,
}

impl Run {
    /// 這次 trigger 的世代（驗證 `completed_generation` 用）。
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

impl Future for Run {
    type Output = Result<RunOutcome, RunCancelled>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        loop {
            match &mut this.role {
                RunRole::Coalescing(sleep) => {
                    if sleep.as_mut().poll(cx).is_pending() {
                        return Poll::Pending;
                    }
                    // Window elapsed: try to claim our flight.
                    let mut st = this.inner.state.lock().unwrap_or_else(|e| e.into_inner());
                    let claimable = matches!(&st.flight, Some(f) if f.executor_gen == this.generation && !f.claimed);
                    if claimable {
                        let claim_gen = st.next_gen;
                        let f = st.flight.as_mut().expect("just checked");
                        f.claimed = true;
                        f.claim_gen = claim_gen;
                        drop(st);
                        this.role = RunRole::Done;
                        this.inner.executes.fetch_add(1, Ordering::SeqCst);
                        return Poll::Ready(Ok(RunOutcome::Execute));
                    }
                    // Defensive: the flight moved on without us (only reachable
                    // after a cancel/promote race); re-register as a waiter.
                    let needs_next = st.flight.as_ref().is_some_and(|f| f.claimed);
                    let (tx, rx) = oneshot::channel();
                    st.waiters
                        .insert(this.generation, Waiter { tx, needs_next });
                    this.role = RunRole::Waiting(rx);
                }
                RunRole::Waiting(rx) => match Pin::new(rx).poll(cx) {
                    Poll::Ready(Ok(outcome)) => {
                        this.role = RunRole::Done;
                        if outcome == RunOutcome::Execute {
                            this.inner.executes.fetch_add(1, Ordering::SeqCst);
                        }
                        return Poll::Ready(Ok(outcome));
                    }
                    Poll::Ready(Err(_)) => {
                        this.role = RunRole::Done;
                        return Poll::Ready(Err(RunCancelled));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                RunRole::Done => panic!("Run polled after completion"),
            }
        }
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        // Executor vanished without finish() (cancel/panic): treat the flight
        // as NOT executed and hand remaining waiters to a fresh run so the
        // queue cannot wedge. No-op when the flight is already gone/moved.
        complete(&self.inner, Some(self.generation), false);
    }
}

/// 結束當前班機並升下一班。
///
/// * `executed` — true 只來自 `finish()`：這班真的跑完，推進
///   `completed_gen`、被涵蓋的等待者拿 `Covered`。false 是 Drop 補救路徑：
///   保守不推進，所有等待者改掛下一班。
/// * `only_gen` — Some 時只結算「自己那班」（Drop 用），避免誤結算別人的班。
fn complete(inner: &Arc<Inner>, only_gen: Option<u64>, executed: bool) {
    let mut st = inner.state.lock().unwrap_or_else(|e| e.into_inner());
    let claim_gen = match &st.flight {
        Some(f) if only_gen.is_none_or(|g| f.executor_gen == g) => {
            // finish() only pairs with a claimed flight.
            if only_gen.is_none() && !f.claimed {
                return;
            }
            f.claim_gen
        }
        _ => return,
    };
    st.flight = None;

    if executed {
        st.completed_gen = st.completed_gen.max(claim_gen.saturating_sub(1));
        let settled: Vec<u64> = st
            .waiters
            .iter()
            .filter(|(_, w)| !w.needs_next)
            .map(|(g, _)| *g)
            .collect();
        for g in settled {
            if let Some(w) = st.waiters.remove(&g) {
                let _ = w.tx.send(RunOutcome::Covered);
            }
        }
    }

    // Promote the oldest waiting generation into a fresh, immediately-claimed
    // flight; everyone else still queued is covered by that run.
    if let Some((&next_gen, _)) = st.waiters.iter().next() {
        let w = st.waiters.remove(&next_gen).expect("just peeked");
        st.flight = Some(Flight {
            executor_gen: next_gen,
            claimed: true,
            claim_gen: st.next_gen,
        });
        for rem in st.waiters.values_mut() {
            rem.needs_next = false;
        }
        let _ = w.tx.send(RunOutcome::Execute);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize as StdAtomic;

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn executor_claims_after_window() {
        let sf = SingleFlight::with_coalesce(Duration::from_millis(50));
        let mut run = sf.trigger().await;
        assert_eq!(run.generation(), 1);
        // Paused time: 40ms is inside the window, the next tick crosses it.
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(5), &mut run)
                .await
                .is_err()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!((&mut run).await.unwrap(), RunOutcome::Execute);
        sf.finish();
        assert_eq!(sf.completed_generation(), 1);
        assert_eq!(sf.execution_count(), 1);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn hundred_concurrent_triggers_run_once() {
        // Paused single-thread runtime: all 100 registrations happen inside the
        // 250ms window before any timer fires.
        let sf = SingleFlight::with_coalesce(Duration::from_millis(250));
        let done = Arc::new(StdAtomic::new(0usize));
        let mut tasks = Vec::new();
        for _ in 0..100 {
            let sf = sf.clone();
            let done = Arc::clone(&done);
            tasks.push(tokio::spawn(async move {
                let mut run = sf.trigger().await;
                let generation = run.generation();
                match (&mut run).await.unwrap() {
                    RunOutcome::Execute => {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                        sf.finish();
                    }
                    RunOutcome::Covered => {
                        assert!(
                            sf.completed_generation() >= generation,
                            "covered waiter must sit behind a completed sync"
                        );
                    }
                }
                done.fetch_add(1, Ordering::SeqCst);
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        assert_eq!(done.load(Ordering::SeqCst), 100);
        assert_eq!(sf.generation(), 100);
        // Property: 100 triggers collapse to 1–2 underlying runs.
        assert!((1..=2).contains(&sf.execution_count()));
        assert_eq!(sf.completed_generation(), 100);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hundred_concurrent_triggers_realtime() {
        // Real-clock variant: the window (1s) dwarfs spawn jitter, so the
        // 100 registrations land in one flight; ≤2 runs keeps the property
        // honest even on a contended CI box.
        let sf = SingleFlight::with_coalesce(Duration::from_millis(1000));
        let mut tasks = Vec::new();
        for _ in 0..100 {
            let sf = sf.clone();
            tasks.push(tokio::spawn(async move {
                let mut run = sf.trigger().await;
                match (&mut run).await.unwrap() {
                    RunOutcome::Execute => {
                        tokio::time::sleep(Duration::from_millis(2)).await;
                        sf.finish();
                    }
                    RunOutcome::Covered => {}
                }
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        assert!((1..=2).contains(&sf.execution_count()));
    }

    #[tokio::test]
    async fn trailing_trigger_gets_a_second_flight() {
        // Final consistency: a trigger arriving while a flight runs is NOT
        // covered by that flight; finish() promotes it to the next one.
        let sf = SingleFlight::with_coalesce(Duration::from_millis(10));
        let mut first = sf.trigger().await;
        assert_eq!((&mut first).await.unwrap(), RunOutcome::Execute);
        let mut late = sf.trigger().await; // flight claimed → needs next
        let late_gen = late.generation();
        sf.finish(); // settles flight 1, promotes `late`
        assert!(
            sf.completed_generation() < late_gen,
            "flight 1 must not claim coverage of a later trigger"
        );
        assert_eq!((&mut late).await.unwrap(), RunOutcome::Execute);
        sf.finish();
        assert!(sf.completed_generation() >= late_gen);
        assert_eq!(sf.execution_count(), 2);
    }

    #[tokio::test]
    async fn window_waiters_are_covered_by_first_flight() {
        let sf = SingleFlight::with_coalesce(Duration::from_millis(30));
        let mut a = sf.trigger().await;
        let mut b = sf.trigger().await; // same window → covered by a's flight
        assert_eq!((&mut a).await.unwrap(), RunOutcome::Execute);
        // b is still parked: coverage only lands after the sync finishes.
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut b)
                .await
                .is_err()
        );
        sf.finish();
        assert_eq!((&mut b).await.unwrap(), RunOutcome::Covered);
        assert!(sf.completed_generation() >= b.generation());
    }

    #[tokio::test]
    async fn dropped_executor_does_not_wedge_the_queue() {
        let sf = SingleFlight::with_coalesce(Duration::from_millis(10));
        let a = sf.trigger().await;
        let mut b = sf.trigger().await;
        drop(a); // executor cancelled before claiming
        // b must still resolve: promotion hands it Execute.
        assert_eq!((&mut b).await.unwrap(), RunOutcome::Execute);
        sf.finish();
    }

    #[tokio::test]
    async fn claimed_executor_drop_requeues_without_advancing_completion() {
        let sf = SingleFlight::with_coalesce(Duration::from_millis(10));
        let mut a = sf.trigger().await;
        assert_eq!((&mut a).await.unwrap(), RunOutcome::Execute);
        drop(a); // panicked executor: conservative, no completed bump
        assert_eq!(sf.completed_generation(), 0);
        // and the gate is reusable afterwards
        let mut c = sf.trigger().await;
        assert_eq!((&mut c).await.unwrap(), RunOutcome::Execute);
        sf.finish();
        assert!(sf.completed_generation() >= c.generation());
    }

    #[tokio::test]
    async fn sequential_triggers_each_execute() {
        let sf = SingleFlight::with_coalesce(Duration::from_millis(1));
        for expect in 1..=3 {
            let mut run = sf.trigger().await;
            assert_eq!(run.generation(), expect);
            assert_eq!((&mut run).await.unwrap(), RunOutcome::Execute);
            sf.finish();
            assert_eq!(sf.completed_generation(), expect);
        }
        assert_eq!(sf.execution_count(), 3);
    }

    #[tokio::test]
    async fn finish_without_flight_is_noop() {
        let sf = SingleFlight::new();
        sf.finish();
        assert_eq!(sf.completed_generation(), 0);
        assert_eq!(sf.generation(), 0);
    }
}
