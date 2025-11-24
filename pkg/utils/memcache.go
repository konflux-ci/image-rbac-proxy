package utils

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/bradfitz/gomemcache/memcache"
	"github.com/sirupsen/logrus"
)

var CacheClient cacheClient

type cacheClient interface {
	Get(key string, val interface{}) error
	Set(key string, val interface{}, ttl int) error
}

type memCache struct {
	client         *memcache.Client
}

// Get retrieves a key from memcache
func (c memCache) Get(key string, val interface{}) error {
	if c.client == nil {
		return errors.New("memcached client is not initialized")
	}

	item, err := c.client.Get(key)
	if err != nil {
		return fmt.Errorf("unable to get key from memcache: %s", err)
	}
	err = json.Unmarshal(item.Value, val)
	if err != nil {
		return fmt.Errorf("unable to parse item from memcache: %s", err)
	}

	return nil
}

// Set stores a key to memcache with specified TTL
func (c memCache) Set(key string, val interface{}, ttl int) error {
	if c.client == nil {
		return errors.New("memcached client is not initialized")
	}

	bytes, err := json.Marshal(val)
	if err != nil {
		return fmt.Errorf("unable to marshal item: %s", err)
	}

	item := &memcache.Item{
		Key:        key,
		Value:      bytes,
		Expiration: int32(ttl),
	}
	err = c.client.Set(item)
	if err != nil {
		return fmt.Errorf("unable to store item: %s", err)
	}
	return err
}

// Generates a memcache client
func InitCacheClient(servers []string){
	logrus.Infof("Memcache servers: %+v", servers)
	CacheClient = memCache{
		client: memcache.New(servers...),
	}
}
