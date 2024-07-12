package tmap

import (
	"sync"
)

// SafeMap 定义一个包含 map 和锁的结构体
type SafeMap struct {
	mu sync.RWMutex
	m  map[string]func(b []byte)
}

// NewSafeMap 创建map
func NewSafeMap() *SafeMap {
	return &SafeMap{m: make(map[string]func(b []byte))}
}

// Put 写操作
func (sm *SafeMap) Put(key string, fn func(b []byte)) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.m[key] = fn
}

// Get 读操作
func (sm *SafeMap) Get(key string) (func(b []byte), bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	fn, ok := sm.m[key]
	return fn, ok
}

// Delete 删除操作
func (sm *SafeMap) Delete(key string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.m, key)
}

func (sm *SafeMap) Foreach(f func(k string, v func(b []byte))) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	for k, v := range sm.m {
		f(k, v)
	}
}
