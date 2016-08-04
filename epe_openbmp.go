package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)


const url_rib = "http://localhost:8001/db_rest/v1/rib"

type tbl_rib struct {
	VRoutes struct {
		Cols int `json:"cols"`
		Data []struct {
			RouterName          string `json:"RouterName"`
			PeerName            string `json:"PeerName"`
			Prefix              string `json:"Prefix"`
			PrefixLen           int    `json:"PrefixLen"`
			Origin              string `json:"Origin"`
			OriginAS            int    `json:"Origin_AS"`
			MED                 int    `json:"MED"`
			LocalPref           int    `json:"LocalPref"`
			NH                  string `json:"NH"`
			ASPath              string `json:"AS_Path"`
			ASPathCount         int    `json:"ASPath_Count"`
			Communities         string `json:"Communities"`
			ExtCommunities      string `json:"ExtCommunities"`
			ClusterList         string `json:"ClusterList"`
			Aggregator          string `json:"Aggregator"`
			PeerAddress         string `json:"PeerAddress"`
			PeerASN             int    `json:"PeerASN"`
			IsIPv4              int    `json:"isIPv4"`
			IsPeerIPv4          int    `json:"isPeerIPv4"`
			IsPeerVPN           int    `json:"isPeerVPN"`
			LastModified        string `json:"LastModified"`
			FirstAddedTimestamp string `json:"FirstAddedTimestamp"`
			PrefixBin           string `json:"prefix_bin"`
			PathID              int    `json:"path_id"`
			Labels              string `json:"labels"`
			RibHashID           string `json:"rib_hash_id"`
			PathHashID          string `json:"path_hash_id"`
			PeerHashID          string `json:"peer_hash_id"`
			RouterHashID        string `json:"router_hash_id"`
			IsWithdrawn         string `json:"isWithdrawn"`
			PrefixBits          string `json:"prefix_bits"`
		} `json:"data"`
		Size        int `json:"size"`
		QueryTimeMs int `json:"queryTime_ms"`
		FetchTimeMs int `json:"fetchTime_ms"`
	} `json:"v_routes"`
}

var rib_data tbl_rib

func main() {
      req, err := http.NewRequest("GET", url_rib, nil)
        if err != nil {
                // handle err
                fmt.Println(err.Error())
                log.Fatalln(err)
        }
        req.Header.Set("Content-Type", "application/json")
        req.SetBasicAuth("openbmp", "CiscoRA")
        resp, err := http.DefaultClient.Do(req)
        if err != nil {
                // handle err
                fmt.Println(err.Error())
                log.Fatalln(err)
        }
        fmt.Printf("The output is:\n %d\n", resp.StatusCode)
        defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	dec.Decode(&rib_data)
        content, _ := ioutil.ReadAll(resp.Body)
	fileType := http.DetectContentType(content)
	fmt.Println("FileType: ", fileType)
	idx := 0
	for  idx < rib_data.VRoutes.Size {
		fmt.Printf("\nRow:%d Prefix:%s ExtCommunities:%s Labels:%s ASP:%s",idx,
		rib_datam.VRoutes.Data[idx].Prefix,
		rib_datam.VRoutes.Data[idx].ExtCommunities,
		rib_datam.VRoutes.Data[idx].Labels,
                rib_datam.VRoutes.Data[idx].ASPath) 
		idx += 1
	}
	fmt.Println(m.VRoutes.Size)

}
