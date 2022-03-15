/*
Copyright (C) 2022 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"strconv"
	"time"
	"net/http"
	"github.com/alecthomas/jsonschema"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
)

// Plugin consts
const (
	PluginRequiredApiVersion        = "0.3.0"
	PluginID                 uint32 = 999
	PluginName                      = "weather"
	PluginDescription               = "Weather plugin for educational purposes"
	PluginContact                   = "github.com/falcosecurity/plugins"
	PluginVersion                   = "0.2.1"
	PluginEventSource               = "weather"
)

///////////////////////////////////////////////////////////////////////////////

type MyPluginConfig struct {
	// This reflects potential internal state for the plugin. In
	// this case, the plugin is configured with a jitter.
	Longitude float64 `json:"lon" jsonschema:"description=Longitude"`
	Latitude float64 `json:"lat" jsonschema:"description=Latitude"`
}

type MyPlugin struct {
	plugins.BasePlugin
	// Contains the init configuration values
	config MyPluginConfig
}

type MyInstance struct {
	source.BaseInstance

	// Copy of the init params from plugin_open()
	initParams string

	// The number of events to return before EOF
	maxEvents uint64

	// A count of events returned. Used to count against maxEvents.
	counter uint64

}

func init() {
	p := &MyPlugin{}
	source.Register(p)
	extractor.Register(p)
}

func (p *MyPluginConfig) setDefault() {
	p.Latitude = 37.5742
	p.Longitude = -122.3297
}

func (m *MyPlugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:                 PluginID,
		Name:               PluginName,
		Description:        PluginDescription,
		Contact:            PluginContact,
		Version:            PluginVersion,
		RequiredAPIVersion: PluginRequiredApiVersion,
		EventSource:        PluginEventSource,
	}
}

func (p *MyPlugin) InitSchema() *sdk.SchemaInfo {
	reflector := jsonschema.Reflector{
		RequiredFromJSONSchemaTags: true, // all properties are optional by default
		AllowAdditionalProperties:  true, // unrecognized properties don't cause a parsing failures
	}
	if schema, err := reflector.Reflect(&MyPluginConfig{}).MarshalJSON(); err == nil {
		return &sdk.SchemaInfo{
			Schema: string(schema),
		}
	}
	return nil
}

func (m *MyPlugin) Init(cfg string) error {
	// The format of cfg is a json object with a single param
	// "jitter", e.g. {"jitter": 10}
	// Empty configs are allowed, in which case the default is used.
	// Since we provide a schema through InitSchema(), the framework
	// guarantees that the config is always well-formed json.
	m.config.setDefault()
	json.Unmarshal([]byte(cfg), &m.config)

	return nil
}

func (m *MyPlugin) Destroy() {
	// nothing to do here
}

func (m *MyPlugin) Open(prms string) (source.Instance, error) {
	// The format of params is a json object with two params:
	// - "start", which denotes the initial value of sample
	// - "maxEvents": which denotes the number of events to return before EOF.
	// Example:
	// {"start": 1, "maxEvents": 1000}
	var obj map[string]uint64
	err := json.Unmarshal([]byte(prms), &obj)
	if err != nil {
		return nil, fmt.Errorf("params %s could not be parsed: %v", prms, err)
	}
	if _, ok := obj["start"]; !ok {
		return nil, fmt.Errorf("params %s did not contain start property", prms)
	}

	if _, ok := obj["maxEvents"]; !ok {
		return nil, fmt.Errorf("params %s did not contain maxEvents property", prms)
	}

	return &MyInstance{
		initParams: prms,
		maxEvents:  obj["maxEvents"],
		counter:    0,
	}, nil
}

func (m *MyInstance) Close() {
	// nothing to do here
}
type Response struct {
	Coord struct {
		Lon float64 `json:"lon"`
		Lat float64 `json:"lat"`
	} `json:"coord"`
	Weather []struct {
		ID          int    `json:"id"`
		Main        string `json:"main"`
		Description string `json:"description"`
		Icon        string `json:"icon"`
	} `json:"weather"`
	Base string `json:"base"`
	Main struct {
		Temp      float64 `json:"temp"`
		FeelsLike float64 `json:"feels_like"`
		TempMin   float64 `json:"temp_min"`
		TempMax   float64 `json:"temp_max"`
		Pressure  int     `json:"pressure"`
		Humidity  int     `json:"humidity"`
	} `json:"main"`
	Visibility int `json:"visibility"`
	Wind       struct {
		Speed float64 `json:"speed"`
		Deg   int     `json:"deg"`
		Gust  float64 `json:"gust"`
	} `json:"wind"`
	Clouds struct {
		All int `json:"all"`
	} `json:"clouds"`
	Dt  int `json:"dt"`
	Sys struct {
		Type    int    `json:"type"`
		ID      int    `json:"id"`
		Country string `json:"country"`
		Sunrise int    `json:"sunrise"`
		Sunset  int    `json:"sunset"`
	} `json:"sys"`
	Timezone int    `json:"timezone"`
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Cod      int    `json:"cod"`
}

func (m *MyInstance) NextBatch(pState sdk.PluginState, evts sdk.EventWriters) (int, error) {
	// Return EOF if reached maxEvents
	if m.counter >= m.maxEvents {
		return 0, sdk.ErrEOF
	}

	var n int
	var evt sdk.EventWriter
	for n = 0; m.counter < m.maxEvents && n < evts.Len(); n++ {
		evt = evts.Get(n)
		m.counter++
		resp, er := http.Get("https://api.openweathermap.org/data/2.5/weather?lat=37.57420&lon=-122.32970&appid=3407ea8207f5dde24295faf44e8d6f9a&units=imperial")
		if er != nil {
			return 0, er
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		var result Response
		if err := json.Unmarshal(body, &result); err != nil {
			return 0, err
		}
		str := strconv.FormatFloat(result.Main.Temp, 'E', -1, 64)

		// It is not mandatory to set the Timestamp of the event (it
		// would be filled in by the framework if set to uint_max),
		// but it's a good practice.
		evt.SetTimestamp(uint64(time.Now().UnixNano()))

		_, err = evt.Writer().Write([]byte(str))
		if err != nil {
			return 0, err
		}
	}
	return n, nil
}

func (m *MyPlugin) String(in io.ReadSeeker) (string, error) {
	evtBytes, err := ioutil.ReadAll(in)
	if err != nil {
		return "", err
	}
	evtStr := string(evtBytes)

	// The string representation of an event is a json object with the sample
	return fmt.Sprintf("{\"sample\": \"%s\"}", evtStr), nil
}

func (m *MyPlugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "float64", Name: "weather.temp", Desc: "Temperature right now"},
	}
}

func (m *MyPlugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	evtBytes, err := ioutil.ReadAll(evt.Reader())
	if err != nil {
		return err
	}
	evtStr := string(evtBytes)
	f, err := strconv.ParseFloat(evtStr, 8)
	if err != nil {
		return err
	}
	switch req.FieldID() {
	case 0: // weather.temp
		req.SetValue(f)
	default:
		return fmt.Errorf("no known field: %s", req.Field())
	}

	return nil
}

func main() {}
