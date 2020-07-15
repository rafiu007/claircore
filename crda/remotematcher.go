package crda

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
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
	ID   string  `json:"id"`
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

type ReportsID struct {
	Response []Report
	Request  []*claircore.IndexRecord
}

func call(records []*claircore.IndexRecord, c chan ReportsID) {
	fmt.Println("Inside call")
	var req []Request
	for _, record := range records {
		req = append(req, Request{Ecosystem: "pypi",
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
		result := ReportsID{Response: da_response, Request: records}
		c <- result
	}
}

func QueryRemoteMatcher(ctx context.Context, records []*claircore.IndexRecord) (map[string][]*claircore.Vulnerability, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "internal/vulnstore/dastore/get").
		Logger()
	ctx = log.WithContext(ctx)
	ch := make(chan ReportsID)
	recordLen := len(records)
	// CRDA remote matcher post API can process `batchSize` records at a time.
	for i := 0; i < recordLen; i += batchSize {
		j := i + batchSize
		if j > recordLen {
			j = recordLen
		}
		go call(records[i:j], ch)
	}

	results := make(map[string][]*claircore.Vulnerability)
	batchLen := int(math.Ceil(float64(recordLen) / float64(batchSize)))
	for i := 0; i < batchLen; i++ {
		res, ok := <-ch
		if !ok {
			break
		}

		req := res.Request
		response := res.Response
		for i, r := range response {
			var vulnArray []*claircore.Vulnerability
			// A package can have multiple vulnerability for single version.
			for _, cve := range r.Result.Recommendation.ComponentAnalysis.Cve {
				vulnArray = append(vulnArray, &claircore.Vulnerability{
					ID:             cve.ID,
					Updater:        "crda",
					Name:           cve.ID,
					Description:    r.Result.Recommendation.Message,
					Severity:       fmt.Sprint(cve.Cvss),
					FixedInVersion: r.Result.Recommendation.ChangeTo,
					Package:        req[i].Package,
				})
			}
			results[req[i].Package.ID] = vulnArray
		}
	}
	return results, nil
}
