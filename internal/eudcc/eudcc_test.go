package eudcc

import (
	"fmt"
	"testing"
)

func TestEUDCCEncodeDecode(t *testing.T) {
	// A test certificate in QR format
	var mycert = []byte(`HC1:NCFOXN%TSMAHN-HFSC41O/XMD/20MSM52 EL1WGTJPBBJRH5$JUQC0ZKLOM9D0WSA3/-2E%5VR5VVBJZI2CB43DIFTWVDPQ3TJC$BDJYD$JC1KT/JCUPT%VDYVDM8CX%LS1J WJP*Q9ZIHAPZXI$MI1VCSWC1QDGZK+9D.XI/VB5DUL6K+ZJT*IGZI.DLGOIM423DJTIJY9JSMCXP4W87LCT8TO.3OZ95EGJIE9MIHJ6W48UK.GCY0$2P/RI SI5K1*TB3:U-1VVS1UU15%HTNIPPAAMI PQVW5 AGCNB-43 X4VV2 73-E3GG3V20-7TZD5CC9T0HD-4CNND*2O%07LPMIH-O92UQ/MHMS3NX73E482W%+NYJ4%Y2OI9ZLE3UQ9H6$R7$ B Y7PR3XZQYH9K.I IVXWVNS4KCTY64SZI$%25I3KC3X83P47LVNBVA%CAK4Q4RVSL71-V/*T6CQG R YDG%H-XHDMHC+BJ3PZ4MH%NL+V.FA%WH9*NBDQKLR3+3KOQ+2JP-T7-ER5S3GBRQ65ZSLT2*%CL.G`)

	// Decode to raw bytes
	referenceRawEUDCC, err := FromQRCodeToRaw(mycert)
	if err != nil {
		t.Fail()
	}

	// Get the Go native struct format
	referenceEUDCC, err := EUDCCFromSerializedCWT(referenceRawEUDCC)
	if err != nil {
		t.Fail()
	}

	// Make a copy of the refPayload to test encode and decode
	refPayload := referenceEUDCC.Payload

	pl2 := *refPayload
	pl2CBOR := PayloadAsCWT(&pl2)
	pl2CBOR2 := make([]byte, len(pl2CBOR))
	copy(pl2CBOR2, pl2CBOR)

	pl3i, err := NewCBORDecoder(pl2CBOR2).DecodeMap()
	if err != nil {
		t.Fail()
	}
	pl3 := PayloadAsJWT(pl3i)
	pl3CBOR := PayloadAsCWT(pl3)

	fmt.Printf("*** PL3 CBOR ***\n%v", pl3CBOR)

	// if bytes.Compare(referenceRawEUDCC, enc) != 0 {
	// 	t.Fail()
	// }

}
