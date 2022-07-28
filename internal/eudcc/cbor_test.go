package eudcc

import (
	"bytes"
	"testing"
)

func BenchmarkCBORDecode(b *testing.B) {
	var payload = []byte{164, 1, 98, 69, 83, 4, 26, 100, 113, 212, 160, 6, 26, 97, 210, 201, 79, 57, 1, 3, 161, 1, 164, 97, 118, 129, 170, 98, 99, 105, 120, 30, 48, 49, 69, 83, 49, 51, 86, 52, 48, 49, 57, 67, 52, 68, 49, 49, 69, 68, 55, 57, 65, 67, 55, 51, 53, 48, 53, 51, 35, 70, 98, 99, 111, 98, 69, 83, 98, 100, 110, 2, 98, 100, 116, 106, 50, 48, 50, 49, 45, 49, 50, 45, 49, 52, 98, 105, 115, 120, 47, 67, 111, 110, 115, 101, 106, 101, 114, 105, 97, 32, 100, 101, 32, 83, 97, 110, 105, 100, 97, 100, 32, 100, 101, 32, 108, 97, 32, 67, 111, 109, 117, 110, 105, 100, 97, 100, 32, 100, 101, 32, 77, 97, 100, 114, 105, 100, 98, 109, 97, 109, 79, 82, 71, 45, 49, 48, 48, 48, 51, 48, 50, 49, 53, 98, 109, 112, 108, 69, 85, 47, 49, 47, 50, 48, 47, 49, 53, 50, 56, 98, 115, 100, 2, 98, 116, 103, 105, 56, 52, 48, 53, 51, 57, 48, 48, 54, 98, 118, 112, 106, 49, 49, 49, 57, 51, 52, 57, 48, 48, 55, 99, 100, 111, 98, 106, 49, 57, 52, 55, 45, 48, 56, 45, 48, 51, 99, 110, 97, 109, 164, 98, 102, 110, 114, 82, 65, 75, 73, 84, 89, 65, 78, 83, 75, 65, 89, 65, 32, 110, 117, 108, 108, 98, 103, 110, 104, 76, 73, 85, 68, 77, 73, 76, 65, 99, 102, 110, 116, 114, 82, 65, 75, 73, 84, 89, 65, 78, 83, 75, 65, 89, 65, 60, 78, 85, 76, 76, 99, 103, 110, 116, 104, 76, 73, 85, 68, 77, 73, 76, 65, 99, 118, 101, 114, 101, 49, 46, 51, 46, 48}
	cb := NewCBORDecoder(payload)

	for i := 0; i < b.N; i++ {
		cb.Reset(payload)
		_, _ = cb.DecodeItem()

	}
}

func TestEncodeDecode(t *testing.T) {
	var mycert = []byte(`HC1:NCFOXN%TSMAHN-HFSC41O/XMD/20MSM52 EL1WGTJPBBJRH5$JUQC0ZKLOM9D0WSA3/-2E%5VR5VVBJZI2CB43DIFTWVDPQ3TJC$BDJYD$JC1KT/JCUPT%VDYVDM8CX%LS1J WJP*Q9ZIHAPZXI$MI1VCSWC1QDGZK+9D.XI/VB5DUL6K+ZJT*IGZI.DLGOIM423DJTIJY9JSMCXP4W87LCT8TO.3OZ95EGJIE9MIHJ6W48UK.GCY0$2P/RI SI5K1*TB3:U-1VVS1UU15%HTNIPPAAMI PQVW5 AGCNB-43 X4VV2 73-E3GG3V20-7TZD5CC9T0HD-4CNND*2O%07LPMIH-O92UQ/MHMS3NX73E482W%+NYJ4%Y2OI9ZLE3UQ9H6$R7$ B Y7PR3XZQYH9K.I IVXWVNS4KCTY64SZI$%25I3KC3X83P47LVNBVA%CAK4Q4RVSL71-V/*T6CQG R YDG%H-XHDMHC+BJ3PZ4MH%NL+V.FA%WH9*NBDQKLR3+3KOQ+2JP-T7-ER5S3GBRQ65ZSLT2*%CL.G`)

	raw, err := FromQRCodeToRaw(mycert)
	if err != nil {
		t.Fail()
	}

	eu, err := EUDCCFromSerializedCWT(raw)
	if err != nil {
		t.Fail()
	}

	sd := make([]any, 4)
	sd[0] = eu.CBORProtectedHeaders
	sd[1] = map[any]any{}
	sd[2] = eu.CBORPayload
	sd[3] = eu.CBORSignature

	enc := NewCBOREncoder().EncodeArray(sd).Bytes()

	if bytes.Compare(raw, enc) != 0 {
		t.Fail()
	}

}

func TestEncodeBstr(t *testing.T) {
	encoder := NewCBOREncoder()

	bs0 := []byte("")
	bs0_r := []byte{0x40}
	enc := encoder.EncodeBytes(bs0).Bytes()
	if bytes.Compare(enc, bs0_r) != 0 {
		t.Fail()
	}

	bs0 = []byte{0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04}
	bs0_r = []byte{0x4c, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04}
	enc = NewCBOREncoder().EncodeBytes(bs0).Bytes()
	if bytes.Compare(enc, bs0_r) != 0 {
		t.Fail()
	}

	bs0 = make([]byte, 65536)
	bs0_r = []byte{0x5a, 0x00, 0x01, 0x00, 0x00, 0x37}
	for i := 0; i < 1000; i++ {
		bs0[i] = 55
	}
	enc = NewCBOREncoder().EncodeBytes(bs0).Bytes()
	if bytes.Compare(enc[:6], bs0_r) != 0 {
		t.Fail()
	}

}
