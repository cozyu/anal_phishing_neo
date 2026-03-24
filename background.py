"""백그라운드 작업 관리 (큐 지원)"""

import threading
from collections import deque


class BackgroundTask:
    """개별 백그라운드 작업"""

    def __init__(self, name, target, args=()):
        self.name = name
        self.done = False
        self.cancelled = False
        self.error = None
        self.result = None
        self.progress = ""
        self._target = target
        self._args = args

    def run(self):
        try:
            self.result = self._target(*self._args, task=self)
        except Exception as e:
            if not self.cancelled:
                self.error = str(e)
        finally:
            self.done = True

    def cancel(self):
        self.cancelled = True

    def set_progress(self, msg):
        self.progress = msg


class TaskQueue:
    """작업 큐 — 현재 작업 완료 후 다음 작업 자동 실행"""

    def __init__(self):
        self._queue = deque()
        self._current = None
        self._completed = []
        self._lock = threading.Lock()
        self._thread = None
        self._pending_remove = []  # 삭제 예약 인덱스

    def add(self, task):
        with self._lock:
            self._queue.append(task)
        self._try_start()

    def _try_start(self):
        with self._lock:
            if self._current and not self._current.done:
                return
            if not self._queue:
                return
            self._current = self._queue.popleft()

        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def _run_loop(self):
        while True:
            with self._lock:
                task = self._current
            if task is None:
                break

            if not task.cancelled:
                task.run()
            else:
                task.done = True

            with self._lock:
                # 삭제 예약된 대기 작업 처리
                for idx in sorted(self._pending_remove, reverse=True):
                    if 0 <= idx < len(self._queue):
                        del self._queue[idx]
                self._pending_remove.clear()

                if not task.cancelled:
                    self._completed.append(task)
                if self._queue:
                    self._current = self._queue.popleft()
                else:
                    self._current = None
                    break

    def cancel_current(self):
        """현재 실행 중인 작업만 취소 (대기 큐는 유지)"""
        with self._lock:
            if self._current and not self._current.done:
                self._current.cancel()

    def remove_pending(self, index):
        """대기 중인 작업 제거"""
        with self._lock:
            if 0 <= index < len(self._queue):
                del self._queue[index]
                return True
            # run_loop 내에서 처리 중일 수 있으므로 예약
            self._pending_remove.append(index)
        return False

    @property
    def current(self):
        with self._lock:
            return self._current

    @property
    def pending(self):
        with self._lock:
            return list(self._queue)

    def pop_completed(self):
        with self._lock:
            tasks = list(self._completed)
            self._completed.clear()
            return tasks

    @property
    def is_busy(self):
        with self._lock:
            return self._current is not None and not self._current.done
