/* ==============================================================================
   CYBERGUARD Frontend — Network Scheduler with Backpressure & Cancellation
   ==============================================================================
   - Concurrency cap: maxConcurrent = 3
   - Per-request timeout via AbortController (default 15s)
   - Exponential backoff on transient network failure
   - cancelAll() for tab visibilitychange & pagehide events
   ============================================================================== */

class NetworkScheduler {
  constructor(concurrency = 3, defaultTimeoutMs = 15000) {
    this.concurrency = concurrency;
    this.defaultTimeoutMs = defaultTimeoutMs;
    this.queue = [];
    this.activeCount = 0;
    this.activeControllers = new Set();
    this.failureStreak = 0;
  }

  enqueue(taskFn, { priority = 0, signal = null, timeout = this.defaultTimeoutMs } = {}) {
    return new Promise((resolve, reject) => {
      this.queue.push({
        taskFn,
        priority,
        signal,
        timeout,
        resolve,
        reject,
        retries: 0
      });
      this.queue.sort((a, b) => b.priority - a.priority);
      this.pump();
    });
  }

  pump() {
    if (this.activeCount >= this.concurrency || this.queue.length === 0) {
      return;
    }

    const item = this.queue.shift();
    this.activeCount++;

    const controller = new AbortController();
    this.activeControllers.add(controller);

    const timeoutId = setTimeout(() => {
      controller.abort("Request timeout");
    }, item.timeout);

    if (item.signal) {
      item.signal.addEventListener("abort", () => controller.abort(item.signal.reason), { once: true });
    }

    item.taskFn(controller.signal)
      .then((result) => {
        clearTimeout(timeoutId);
        this.failureStreak = 0;
        if (typeof window.store?.setConnection === "function" && navigator.onLine) {
          window.store.setConnection("online");
        }
        item.resolve(result);
      })
      .catch((error) => {
        clearTimeout(timeoutId);
        const isAbort = controller.signal.aborted;

        if (!isAbort && item.retries < 2 && navigator.onLine) {
          item.retries++;
          this.failureStreak++;
          if (this.failureStreak >= 2 && typeof window.store?.setConnection === "function") {
            window.store.setConnection("reconnecting");
          }
          const backoffDelay = Math.min(1000 * Math.pow(2, item.retries), 10000);
          setTimeout(() => {
            this.queue.unshift(item);
            this.pump();
          }, backoffDelay);
        } else {
          if (!isAbort && !navigator.onLine && typeof window.store?.setConnection === "function") {
            window.store.setConnection("offline");
          }
          item.reject(error);
        }
      })
      .finally(() => {
        this.activeControllers.delete(controller);
        this.activeCount--;
        this.pump();
      });

    this.pump();
  }

  cancelAll(reason = "Scheduler cancellation") {
    for (const controller of this.activeControllers) {
      try {
        controller.abort(reason);
      } catch (err) {
        console.warn("[scheduler] Error aborting controller:", err);
      }
    }
    this.activeControllers.clear();
    while (this.queue.length > 0) {
      const item = this.queue.shift();
      item.reject(new DOMException("Cancelled by scheduler", "AbortError"));
    }
    this.activeCount = 0;
  }
}

const scheduler = new NetworkScheduler(3, 15000);

/* -----------------------------
   LIFECYCLE & CANCELLATION HANDLERS
----------------------------- */
document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    scheduler.cancelAll("Visibility hidden");
  }
});

window.addEventListener("pagehide", () => {
  scheduler.cancelAll("Page hide");
});

window.addEventListener("beforeunload", () => {
  scheduler.cancelAll("Page unload");
});

window.scheduler = scheduler;
window.NetworkScheduler = NetworkScheduler;
