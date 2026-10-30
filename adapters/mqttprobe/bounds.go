// SPDX-License-Identifier: Apache-2.0

package mqttprobe

import (
	"fmt"
	"net"
	"time"
)

// Paho advertises MaximumPacketSize but its decoder allocates the received
// remaining length. Bound the frame before that allocation, including peers
// that ignore the negotiated limit. This wrapper does not interpret MQTT data.
type packetConn struct {
	net.Conn
	writeTimeout time.Duration
	header       bool
	lengthBytes  int
	length       int
	remaining    int
}

func (c *packetConn) Read(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	if c.remaining > 0 {
		if len(data) > c.remaining {
			data = data[:c.remaining]
		}
		n, err := c.Conn.Read(data)
		c.remaining -= n
		return n, err
	}
	if !c.header {
		n, err := c.Conn.Read(data[:1])
		if n == 1 {
			c.header = true
			c.lengthBytes = 0
			c.length = 0
		}
		return n, err
	}
	n, err := c.Conn.Read(data[:1])
	if n != 1 {
		return n, err
	}
	value := data[0]
	c.length += int(value&0x7f) << (7 * c.lengthBytes)
	c.lengthBytes++
	if c.length > MaxPacketSize || c.lengthBytes > 4 || (c.lengthBytes == 4 && value&0x80 != 0) {
		return 0, fmt.Errorf("MQTT frame exceeds the receive limit")
	}
	if value&0x80 == 0 {
		c.remaining = c.length
		c.header = false
	}
	return n, err
}

func (c *packetConn) Write(data []byte) (int, error) {
	if err := c.Conn.SetWriteDeadline(time.Now().Add(c.writeTimeout)); err != nil {
		return 0, err
	}
	return c.Conn.Write(data)
}
