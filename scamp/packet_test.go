package scamp

import "testing"
import "bytes"
import "bufio"
import "fmt"

func TestReadHeaderPacketOK(t *testing.T) {
	byteBuf := []byte("HEADER 1 46\r\n{\"action\":\"foo\",\"version\":1,\"envelope\":\"json\"}END\r\n")
	byteReader := bufio.NewReader(bytes.NewReader(byteBuf))

	packet, err := ReadPacket(byteReader)
	if err != nil {
		t.Errorf("got err `%s`", err)
		t.FailNow()
	}
	if packet.packetType != HEADER {
		t.Errorf("packetType was not parsed correctly. packet.packetType: `%d`", packet.packetType)
		t.FailNow()
	}
	if len(packet.body) != 0 {
		t.Errorf("header packet should not provide body. packet.body: `%s`", packet.body)
		t.FailNow()
	}

	header := packet.packetHeader
	emptyHeader := PacketHeader{}
	if header == emptyHeader {
		t.Errorf("header was not parsed")
		t.FailNow()
	}
	if header.Version != 1 {
		t.Errorf("expected header.version to be 1 but got %d", header.Version)
		t.FailNow()
	}
	if header.Action != "foo" {
		t.Errorf("expected header.action to be `foo` but got `%s`", header.Action)
		t.FailNow()
	}
	if header.Envelope != ENVELOPE_JSON {
		t.Errorf("expected header.envelope to be ENVELOPE_JSON (%d) but got %d", ENVELOPE_JSON, header.Envelope)
		t.FailNow()
	}
}

func TestReadDataPacketOK(t *testing.T) {
	byteBuf := []byte("DATA 1 46\r\n{\"action\":\"foo\",\"version\":1,\"envelope\":\"json\"}END\r\n")
	byteReader := bufio.NewReader(bytes.NewReader(byteBuf))

	packet, err := ReadPacket(byteReader)
	if err != nil {
		t.Errorf("got err `%s`", err)
		t.FailNow()
	}
	if packet.packetType != DATA {
		t.Errorf("packetType was not parsed correctly. packet.packetType: `%d`", packet.packetType)
		t.FailNow()
	}
	expectedBody := []byte(`{"action":"foo","version":1,"envelope":"json"}`)
	if !bytes.Equal(packet.body, expectedBody) {
		t.Errorf("bad packet body parse. expected `%s`, got: `%s`", expectedBody, packet.body)
		t.FailNow()
	}

	emptyHeader := PacketHeader{}
	if packet.packetHeader != emptyHeader {
		t.Errorf("packet header should not be set")
		t.FailNow()
	}
}

func TestFailGarbage(t *testing.T) {
	byteBuf := []byte("asdfasdf")
	byteReader := bufio.NewReader(bytes.NewReader(byteBuf))

	_, err := ReadPacket(byteReader)
	if err == nil {
		t.Errorf("expected non-nil err", err)
		t.FailNow()
	}
	if fmt.Sprintf("%s", err) != "EOF" {
		t.Errorf("expected `%s`, got `%s`", "header must have 3 parts", err)
		t.FailNow()
	}
}

func TestFailHeaderParams(t *testing.T) {
	Initialize()
	byteReader := bufio.NewReader(bytes.NewReader([]byte("HEADER 1\r\n{\"action\":\"foo\",\"version\":1,\"envelope\":\"json\"}END\r\n")))

	_, err := ReadPacket(byteReader)
	if err == nil {
		t.Fatalf("expected non-nil err", err)
	}
	if err.Error() != "EOF" {
		t.Fatalf("expected `%s`, got `%s`", "expected integer", err)
	}
}

// TODO: string cmp not working well
// func TestFailHeaderBadType(t *testing.T){
//   byteReader := bufio.NewReader(bytes.NewReader( []byte("HEADER a b\r\n{\"action\":\"foo\",\"version\":1,\"envelope\":\"json\"}END\r\n") )

//   _,err := ReadPacket( byteReader )
//   if err == nil {
//     t.Errorf("expected non-nil err", err)
//     t.FailNow()
//   }
//   if(fmt.Sprintf("%s", err) != "header must have 3 parts") {
//     t.Errorf("expected `%s`, got `%s`", "strconv.ParseInt: parsing \"a\": invalid syntax", err)
//     t.FailNow()
//   }
// }

func TestFailTooFewBodyBytes(t *testing.T) {
	byteReader := bufio.NewReader(bytes.NewReader([]byte("HEADER 1 46\r\n{\"\":\"foo\",\"version\":1,\"\":\"json\"}END\r\n")))

	_, err := ReadPacket(byteReader)
	if err == nil {
		t.Errorf("expected non-nil err", err)
		t.FailNow()
	}
	expected := "failed to read body"
	if fmt.Sprintf("%s", err) != expected {
		t.Errorf("expected `%s`, got `%s`", expected, err)
		t.FailNow()
	}
}

func TestFailTooManyBodyBytes(t *testing.T) {
	byteReader := bufio.NewReader(bytes.NewReader([]byte("HEADER 1 46\r\n{\"\":\"foo\",\"version\":1,\"\":\"jsonasdfasdfasdfasdf\"}END\r\n")))

	_, err := ReadPacket(byteReader)
	expected := "packet was missing trailing bytes"
	if fmt.Sprintf("%s", err) != expected {
		t.Errorf("expected `%s`, got `%s`", "packet was missing trailing bytes", expected, err)
		t.FailNow()
	}
}

func TestWriteHeaderPacket(t *testing.T) {
	packet := Packet{
		packetType:  HEADER,
		msgNo: 0,
		packetHeader: PacketHeader{
			Action:    "hello.helloworld",
			Envelope:  ENVELOPE_JSON,
			RequestId: 1,
			Version:   1,
			MessageType: MESSAGE_TYPE_REQUEST,
		},
		body: []byte(""),
	}
	expected := []byte("HEADER 0 92\r\n{\"action\":\"hello.helloworld\",\"envelope\":\"json\",\"request_id\":1,\"type\":\"request\",\"version\":1}\nEND\r\n")

	buf := new(bytes.Buffer)
	bytesWritten,err := packet.Write(buf)
	if err != nil {
		t.Errorf("unexpected error while writing to buf `%s`", err)
		t.FailNow()
	} else if bytesWritten != len(expected) {
		t.Errorf("failed to write all bytes. expected %d got %d", len(expected), bytesWritten)
		t.FailNow()
	}

	if !bytes.Equal(expected, buf.Bytes()) {
		t.Errorf("expected\n`%s`\n`%v`\ngot\n`%s`\n`%v`\n", expected, expected, buf.Bytes(), buf.Bytes())
		t.FailNow()
	}
}

func TestWriteEofPacket(t *testing.T) {
	packet := Packet{
		packetType:  EOF,
		msgNo: 0,
		body:        []byte(""),
	}
	expected := []byte("EOF 0 0\r\nEND\r\n")

	buf := new(bytes.Buffer)
	bytesWritten,err := packet.Write(buf)
	if err != nil {
		t.Errorf("unexpected error while writing to buf `%s`", err)
		t.FailNow()
	} else if bytesWritten != len(expected) {
		t.Errorf("failed to write all bytes. expected %d got %d", len(expected), bytesWritten)
		t.FailNow()
	}

	if !bytes.Equal(expected, buf.Bytes()) {
		t.Errorf("expected\n`%s`\n`%v`\ngot\n`%s`\n`%v`\n", expected, expected, buf.Bytes(), buf.Bytes())
		t.FailNow()
	}
}
