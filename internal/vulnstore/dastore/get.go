package dastore

import (
	"context"
	"fmt"

	//"strconv"

	"github.com/rs/zerolog"

	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/vulnstore"
)

//Creating a structre for json
type Cve struct {
	Idd  string  `json:"id"`
	Cvss float32 `json:"cvss"`
}

//Creating a structre for json
type ComponentAnalysis struct {
	Cve []Cve `json:"cve"`
}

//Creating a structre for json
type Recommendation struct {
	ChangeTo          string            `json:"change_to"`
	Message           string            `json:"message"`
	ComponentAnalysis ComponentAnalysis `json:"component-analyses"`
}

//Creating a structre for json
type Result struct {
	Recommendation Recommendation `json:"recommendation"`
}

//Report Creating a structre for json
type Report struct {
	Result Result `json:"result"`
}

func get(ctx context.Context, records []*claircore.IndexRecord, opts vulnstore.GetOpts) (map[string][]*claircore.Vulnerability, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "internal/vulnstore/postgres/get").
		Logger()
	ctx = log.WithContext(ctx)

	s1 := "https://f8a-analytics-2445582058137.production.gw.apicast.io/api/v1/component-analyses/pypi/"
	s2 := "?user_key=9e7da76708fe374d8c10fa752e72989f"

	results := make(map[string][]*claircore.Vulnerability)
	//position := 0

	for _, j := range records {
		log.Print(j)
		//dynamically creating the package
		url := s1 + j.Package.Name + "/" + j.Package.Version + s2

		resultjson, _ := http.Get(url)

		body, _ := ioutil.ReadAll(resultjson.Body)
		fmt.Println(string(body))
		reports := Report{}
		err := json.Unmarshal(body, &reports)

		if err != nil {
			fmt.Println(err)
		}

		if len(reports.Result.Recommendation.ComponentAnalysis.Cve) > 0 {
			fmt.Println(reports.Result.Recommendation.ComponentAnalysis.Cve[0].Idd)
			fmt.Println("...................................................................................................................................................")
			v := &claircore.Vulnerability{

				ID:                 j.Package.ID,
				Updater:            "abc",
				Name:               j.Package.Name,
				Description:        reports.Result.Recommendation.Message,
				Links:              "dummy_flask",
				Severity:           fmt.Sprint(reports.Result.Recommendation.ComponentAnalysis.Cve[0].Cvss),
				NormalizedSeverity: "dummy_flask",
				FixedInVersion:     reports.Result.Recommendation.ChangeTo,
				Package: &claircore.Package{ID: "0",
					Name:    "xyz",
					Version: "v0.0"},
				Dist: &claircore.Distribution{},
				Repo: &claircore.Repository{},
			}

			//key := strconv.Itoa(position)

			results[j.Package.ID] = append(results[j.Package.ID], v)

			//position = position + 1
		} else {
			fmt.Println("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
		}

		fmt.Printf("%v %v", j.Package.Name, j.Package.Version)

	}
	fmt.Println("...............................................................................................................................")
	fmt.Println(results["0"])
	//fmt.Println(position)

	return results, nil

}
