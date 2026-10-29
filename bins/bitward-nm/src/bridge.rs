//! BTP 橋接：Hello/Welcome 握手 + 讀寫任務 + rid 配對（形态同 `bitward-mcp` 的 bridge）。
//! 斷線即標記 dead 並清空待答請求；主迴程據此對所有 pending 回 error 後結束。
//! 這裡不做任何政策判斷——授權、budget、核准、淨化全在 daemon `call()`（契約 §2.3）。

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot, watch};

use bw_btp::{read_server, write_client};
use bw_proto::{Auth, Call, ClientMsg, PROTO_VERSION, ProtoVersion, Response, ServerMsg, WtpError};

struct Inner {
    pending: Mutex<HashMap<u64, oneshot::Sender<Result<Response, WtpError>>>>,
    dead: watch::Sender<Option<String>>,
}

impl Inner {
    fn kill(&self, reason: String) {
        self.dead.send_modify(|d| {
            if d.is_none() {
                *d = Some(reason.clone());
            }
        });
        // drop sender ⇒ 等待中的 invoke 收到 RecvError，轉成 dead 原因。
        self.pending.lock().expect("bridge mutex poisoned").clear();
    }
}

pub struct Bridge {
    inner: Arc<Inner>,
    write_tx: mpsc::UnboundedSender<ClientMsg>,
    next_rid: AtomicU64,
}

impl Bridge {
    /// 呼叫端須已完成 OS 層連線（UDS）；這裡講 BTP：Hello → Welcome。
    pub async fn connect<S>(stream: S, auth: Auth) -> Result<Bridge, String>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut rd, mut wr) = tokio::io::split(stream);
        write_client(
            &mut wr,
            &ClientMsg::Hello {
                version: ProtoVersion(PROTO_VERSION),
                auth,
                wants: vec![],
            },
        )
        .await
        .map_err(|e| format!("btp hello: {e}"))?;
        match read_server(&mut rd).await {
            Ok(ServerMsg::Welcome { proto, .. }) => {
                if proto > PROTO_VERSION {
                    return Err(format!("daemon proto {proto} > nm {PROTO_VERSION}"));
                }
            }
            Ok(other) => return Err(format!("expected Welcome, got {other:?}")),
            Err(e) => return Err(format!("btp welcome: {e}")),
        }
        let inner = Arc::new(Inner {
            pending: Mutex::new(HashMap::new()),
            dead: watch::channel(None).0,
        });
        let (write_tx, mut write_rx) = mpsc::unbounded_channel();
        {
            let inner = inner.clone();
            tokio::spawn(async move {
                while let Some(msg) = write_rx.recv().await {
                    if let Err(e) = write_client(&mut wr, &msg).await {
                        inner.kill(format!("btp write: {e}"));
                        break;
                    }
                }
            });
        }
        {
            let inner = inner.clone();
            tokio::spawn(async move {
                loop {
                    match read_server(&mut rd).await {
                        Ok(ServerMsg::Reply { rid, outcome }) => {
                            if let Some(tx) = inner
                                .pending
                                .lock()
                                .expect("bridge mutex poisoned")
                                .remove(&rid)
                            {
                                let _ = tx.send(outcome);
                            }
                        }
                        // wants=∅ 不該有非 Reply 幀；出現即忽略，保底不吞掉後續 Reply。
                        Ok(_) => {}
                        Err(e) => {
                            inner.kill(format!("btp read: {e}"));
                            break;
                        }
                    }
                }
            });
        }
        Ok(Bridge {
            inner,
            write_tx,
            next_rid: AtomicU64::new(1),
        })
    }

    /// 回 Err＝橋已死（呼叫端應結束程序）；回 Ok(Err(WtpError))＝daemon 的協定級錯誤。
    /// 無逾時是刻意的：daemon 可能阻塞等人工核准（§2.3），shim 透明轉譯。
    pub async fn invoke(&self, call: Call) -> Result<Result<Response, WtpError>, String> {
        let rid = self.next_rid.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        {
            let mut p = self.inner.pending.lock().expect("bridge mutex poisoned");
            if self.inner.dead.borrow().is_some() {
                return Err(self.dead_reason());
            }
            p.insert(rid, tx);
        }
        if let Err(e) = self
            .write_tx
            .send(ClientMsg::Invoke { rid, call })
            .map_err(|_| self.dead_reason())
        {
            self.inner
                .pending
                .lock()
                .expect("bridge mutex poisoned")
                .remove(&rid);
            return Err(e);
        }
        match rx.await {
            Ok(outcome) => Ok(outcome),
            Err(_) => Err(self.dead_reason()),
        }
    }

    fn dead_reason(&self) -> String {
        self.inner
            .dead
            .borrow()
            .clone()
            .unwrap_or_else(|| "bridge closed".into())
    }

    /// 主迴程 select 這個信號：橋斷 ⇒ 對 pending 回 error 後以錯結束。
    pub async fn dead(&self) {
        let mut rx = self.inner.dead.subscribe();
        loop {
            if rx.borrow().is_some() {
                return;
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
    }
}
