package crda

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/quay/claircore"
)

const (
	batchSize = 10
	url       = `https://f8a-analytics-2445582058137.production.gw.apicast.io:443/api/v1/component-analyses/?user_key=9e7da76708fe374d8c10fa752e72989f`
)

// Build struct to model CRDA ComponentAnalysis response.
type Cvee struct {
	Cve_id   []string `json:"cve_id"`
	Fixed_in []string `json:"fixed_in"`
}

type Data struct {
	Cvee Cvee `json:"cve"`
}

type Cve struct {
	Idd  string  `json:"id"`
	Cvss float32 `json:"cvss"`
}

type ComponentAnalysis struct {
	Cve []Cve `json:"cve"`
}

type Recommendation struct {
	ChangeTo          string            `json:"change_to"`
	Message           string            `json:"message"`
	ComponentAnalysis ComponentAnalysis `json:"component-analyses"`
}

type Result struct {
	Recommendation Recommendation `json:"recommendation"`
	Data           []Data         `json:"data"`
}

type Report struct {
	Result Result `json:"result"`
}

type Request struct {
	Ecosystem string `json:"ecosystem"`
	Package   string `json:"package"`
	Version   string `json:"version"`
}

type ReportsId struct {
	Response []Report
	Request []*claircore.IndexRecord
}

func call(records []*claircore.IndexRecord, c chan ReportsId) {
	fmt.Println("Inside call")
	var req []Request
	for _, record := range records {
		req = append(req, Request { Ecosystem: "pypi",
												Package: record.Package.Name,
												Version: record.Package.Version})
	}
	jsonValue, _ := json.Marshal(req)
	response, err := http.Post(url, "application/json", bytes.NewBuffer(jsonValue))
	if err != nil {
		fmt.Printf("The HTTP request failed with error %s\n", err)
	} else {
		var da_response []Report
		data, _ := ioutil.ReadAll(response.Body)
		err = json.Unmarshal(data, &da_response)
		if err != nil {
			fmt.Println(err)
		}
		result := ReportsId{Response: da_response, Request: records}
		c <- result
	}
}

func QueryRemoteMatcher(ctx context.Context, records []*claircore.IndexRecord) (map[string][]*claircore.Vulnerability, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "internal/vulnstore/dastore/get").
		Logger()
	ctx = log.WithContext(ctx)
	results := make(map[string][]*claircore.Vulnerability)
	ch := make(chan ReportsId)
	count := 0
	// CRDA remote matcher post API can process `batchSize` records at a time.
	for i := 0; i < len(records); i += batchSize {
		j := i + batchSize
		if j > len(records) {
			j = len(records)
		}
		count ++
		go call(records[i:j], ch)
	}

	for i := 0; i < count; i++ {
		res, ok := <-ch
		if !ok {
			break
		}
		req := res.Request
		response := res.Response
		for i := 0; i < len(response); i++ {
			if len(response[i].Result.Recommendation.ComponentAnalysis.Cve) > 0 {
				var vulnArray []*claircore.Vulnerability
				vulnArray = append(vulnArray, &claircore.Vulnerability{
					ID:          req[i].Package.ID,
					Updater:     "",
					Name:        response[i].Result.Recommendation.ComponentAnalysis.Cve[0].Idd,
					Description: response[i].Result.Recommendation.Message,
					Links:       "",
					Severity:    fmt.Sprint(response[i].Result.Recommendation.ComponentAnalysis.Cve[0].Cvss),
					// 						// NormalizedSeverity: "",
					FixedInVersion: response[i].Result.Data[0].Cvee.Fixed_in[0],
					Package: &claircore.Package{ID: "0",
						Name:    "xyz",
						Version: "v0.0"},
					Dist: &claircore.Distribution{},
					Repo: &claircore.Repository{},
				})

				results[req[i].Package.ID] = vulnArray
			}

		}

	}
	return results, nil

}
