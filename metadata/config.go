package metada

import (
  "io"
  
  "github.com/golang/protobuf/jsonpb"
)

func WriteConfig(config *Config, out io.Writer) error {
  m := jsonpb.Marshaler {
    EmitDefaults: true,
    EnumAsInts: false,
    Indent: "\t",
    OrigName: true,
  }
  if err := m.Marshal(out, config); err != nil {
    return err
  }
  _, err := out.Write([]byte{'\n'})
  return err
}

func ReadConfig(in io.Reader) (*Config, error) {
  config := new(Config)
  u := jsonpb.Unmarshaler{
    AllowUnknownFields: true,
  }
  return config, u.Unmarshal(in, config)
}

