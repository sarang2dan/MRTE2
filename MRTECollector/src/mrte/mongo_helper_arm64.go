//go:build arm64

package mrte

import (
	"encoding/binary"
)

func (p *MysqlRequest) GetPayLoadSize() int {
	return int(4 + (0xFFFFFF & binary.BigEndian.Uint32(p.Data)))
}
