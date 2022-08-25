//go:build amd64

package mrte

import (
	"encoding/binary"
)

func (p *MysqlRequest) GetPayLoadSize() int {
	return int(4 + (0xFFFFFF & binary.LittleEndian.Uint32(p.Data)))
}
