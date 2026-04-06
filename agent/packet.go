package main

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/fatih/color"
)

//?============================================================================+
//?  This file implements the functionality for creating and parsing           |
//?  parameters in the v4 telemetry packet design. Use ParseParameters(...)    |
//?============================================================================+

// Outer function that will parse every parameter in provided data buffer.
// Name must not be null-terminated. Size must be size in bytes. Header portion must be null-terminated.
func ParseParameters(data []byte) []Parameter {
	var params []Parameter
	cursor := 0
	for cursor < len(data) {
		parameter := ReadAnsiString(data[cursor:])
		cursor += len(parameter) + 1 // +1 because null-terminator occupies one byte after

		// -1 so you wont get out of bounds error, but prevent off-by-one error.
		param, err := ParseParameterString(parameter, data[cursor-1:])
		if err != nil || param.Buffer == nil {
			if err != nil {
				color.Red("\n[!] Failed to parse parameter: %v", err)
			}
			if len(parameter) == 0 {
				break // prevent infinite loop
			}
			continue
		}
		cursor += len(param.Buffer)
		params = append(params, param)
	}
	return params
}

// takes in the current parameters header, and the entire buffer after it
func ParseParameterString(header string, data []byte) (Parameter, error) {
	var (
		param   Parameter
		isArray = false
	)

	// skip empty reads. minimum possible size of header is 3 (a:b)
	if header == "" || len(header) < 2 {
		return Parameter{}, nil
	}
	ptype := header[:1]
	parts := strings.Split(header[1:], "/")
	// non-array types should have only one string in head (no "/")
	if len(parts) > 1 {
		if len(parts[1]) == 0 {
			return Parameter{}, fmt.Errorf("invalid header: size (%s)", header)
		}
		param.Name = parts[0]
		size, err := strconv.Atoi(parts[1])
		if err != nil {
			return Parameter{}, fmt.Errorf("failed to read size into integer: %v (%s)", err, header)
		}
		// add array defined bytes into the parameter buffer
		param.Buffer = append([]byte(nil), data[:size]...)
		isArray = true
	} else {
		param.Name = header[1:]
	}

	param.Type = uint8(GetParameterType(ptype))

	// remove possible null-terminator from first byte
	if len(data) > 0 && data[0] == '\000' {
		data = data[1:]
	}
	if !isArray { // now get data buffer if it wasnt array
		switch int(param.Type) {
		case PARAMETER_ANSISTRING:
			str := ReadAnsiString(data)
			param.Buffer = append([]byte(nil), data[:len(str)+1]...)
		case PARAMETER_BOOLEAN, PARAMETER_UINT32:
			param.Buffer = append([]byte(nil), data[:4]...)
		case PARAMETER_UINT64, PARAMETER_POINTER:
			param.Buffer = append([]byte(nil), data[:8]...)
		}
	}
	return param, nil
}

// Print the provided parameters
func PrintParameters(params map[string]Parameter) {
	for _, param := range params {
		fmt.Printf("\t%s: %v", param.Name, param.GetValue())
	}
}

// Return the dynamic parameter as a regular Go value.
// This method is generally used to print a value with "%v"
// Array values are returned as a list of bullet points (i.e. string)
func (p Parameter) GetValue() any {
	switch p.Type {
	case PARAMETER_ANSISTRING:
		return ReadAnsiStringValue(p.Buffer)
	case PARAMETER_ASTR_ARRAY:
		return GetStringArrayFromBuffer(p.Buffer)
	case PARAMETER_BOOLEAN:
		return binary.LittleEndian.Uint32(p.Buffer) == 1
	case PARAMETER_BOOLEAN_ARRAY:
		return GetBooleanArrayFromBuffer(p.Buffer)
	case PARAMETER_UINT32:
		val := binary.LittleEndian.Uint32(p.Buffer)
		if p.Domain == 0 {
			return val
		}
		return InterpretBitmaskValue((Bitmask)(val), p.Domain)
	case PARAMETER_UINT32_ARRAY:
		return GetUint32ArrayFromBuffer(p.Buffer)
	case PARAMETER_UINT64:
		return binary.LittleEndian.Uint64(p.Buffer)
	case PARAMETER_UINT64_ARRAY:
		return GetUint64ArrayFromBuffer(p.Buffer)
	case PARAMETER_POINTER:
		return fmt.Sprintf("%p", binary.LittleEndian.Uint64(p.Buffer))
	case PARAMETER_POINTER_ARRAY:
		return GetPointerArrayFromBuffer(p.Buffer)
	case PARAMETER_BYTES:
		return p.Buffer
	}
	return "(invalid parameter)"
}

// Read the type of a (v4) parameter from the header string
func GetParameterType(ptype string) uint8 {
	switch ptype[0] {
	case 's':
		return uint8(PARAMETER_ANSISTRING)
	case 'S':
		return uint8(PARAMETER_ASTR_ARRAY)
	case 'd':
		return uint8(PARAMETER_UINT32)
	case 'D':
		return uint8(PARAMETER_UINT32_ARRAY)
	case 'q':
		return uint8(PARAMETER_UINT64)
	case 'Q':
		return uint8(PARAMETER_UINT64_ARRAY)
	case 'p':
		return uint8(PARAMETER_POINTER)
	case 'P':
		return uint8(PARAMETER_POINTER_ARRAY)
	case 'b':
		return uint8(PARAMETER_BOOLEAN)
	case 'B':
		return uint8(PARAMETER_BOOLEAN_ARRAY)
	case 'x':
		return uint8(PARAMETER_BYTES)
	}
	return 0
}

// Portrays the content of a C string array buffer
// Used to portray the contents of a dynamic Parameter
func GetStringArrayFromBuffer(buf []byte) string {
	var builder strings.Builder
	for i := 0; i < len(buf); {
		str := ReadAnsiStringValue(buf[i:])
		if len(str) == 0 {
			break
		}
		builder.WriteString("\n\t- ")
		builder.WriteString(str)
		i += len(str)
	}
	builder.WriteString("\n")
	return builder.String()
}

// Portrays the content of a uint32 array buffer
// Used to portray the contents of a dynamic Parameter
func GetUint32ArrayFromBuffer(buf []byte) string {
	var builder strings.Builder
	for i := 0; i < len(buf); i += 4 {
		val := binary.LittleEndian.Uint32(buf[i:])
		builder.WriteString("\n\t- ")
		builder.WriteString(strconv.FormatUint(uint64(val), 10))
	}
	builder.WriteString("\n")
	return builder.String()
}

// Portrays the content of a uint64 array buffer
// Used to portray the contents of a dynamic Parameter
func GetUint64ArrayFromBuffer(buf []byte) string {
	var builder strings.Builder
	for i := 0; i < len(buf); i += 8 {
		val := binary.LittleEndian.Uint64(buf[i:])
		builder.WriteString("\n\t- ")
		builder.WriteString(strconv.FormatUint(val, 10))
	}
	builder.WriteString("\n")
	return builder.String()
}

// Portrays the content of a 64-bit pointer array buffer
// Used to portray the contents of a dynamic Parameter
func GetPointerArrayFromBuffer(buf []byte) string {
	var builder strings.Builder
	for i := 0; i < len(buf); i += 8 {
		val := binary.LittleEndian.Uint64(buf[i:])
		builder.WriteString("\n\t- ")
		builder.WriteString("0x")
		builder.WriteString(strconv.FormatUint(val, 16))
	}
	builder.WriteString("\n")
	return builder.String()
}

// Portrays the content of a boolean array buffer
// Used to portray the contents of a dynamic Parameter
// This assumes 4 bytes are used for a boolean
func GetBooleanArrayFromBuffer(buf []byte) string {
	var builder strings.Builder
	for i := 0; i < len(buf); i += 4 {
		val := binary.LittleEndian.Uint32(buf[i:])
		builder.WriteString("\n\t- ")
		if val == 0 {
			builder.WriteString("FALSE")
		} else {
			builder.WriteString("TRUE")
		}
	}
	builder.WriteString("\n")
	return builder.String()
}
