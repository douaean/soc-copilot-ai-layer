from .wazuh_client import get_client



class WazuhOpenSearch:


    def __init__(self):

        self.client = get_client()



    def extract_alerts(self, size=100):

        """
        Extraction de toutes les alertes Wazuh
        depuis OpenSearch
        """

        query = {

            "query": {

                "match_all": {}

            }

        }



        response = self.client.search(

            index="wazuh-alerts-*",

            body=query,

            size=size,

            sort=[
                {
                    "@timestamp": {
                        "order": "desc"
                    }
                }
            ]

        )


        alerts = []


        for hit in response["hits"]["hits"]:

            alert = hit["_source"]

            alerts.append(alert)


        return alerts