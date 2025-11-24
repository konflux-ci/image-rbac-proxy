package tests

import (
	"errors"
	"encoding/json"
	"fmt"
)

// MockCache is a local in-memory cache used for testing
type MockCache struct {
	Data map[string][]byte
}

// Get retrieves an item from cache
func (c *MockCache) Get(key string, val interface{}) error {
	if c.Data == nil {
		c.Data = make(map[string][]byte)
	}

	item, ok := c.Data[key]
	if !ok {
		return errors.New("key does not exist in cache")
	}

	err := json.Unmarshal(item, &val)
	if err != nil {
		return fmt.Errorf("unable to parse item from cache: %s", err)
	}

	return nil
}

// Set stores an item in cache (and does not honor TTL)
func (c *MockCache) Set(key string, val interface{}, _ int) error {
	if c.Data == nil {
		c.Data = make(map[string][]byte)
	}

	bytes, err := json.Marshal(val)
	if err != nil {
		return fmt.Errorf("unable to marshal item: %s", err)
	}
	c.Data[key] = bytes

	return nil
}
