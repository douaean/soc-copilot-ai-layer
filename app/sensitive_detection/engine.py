import json
import os


class SensitiveDataCorrelator:


    def __init__(self):

        self.output_file = (
            "output/sensitive_detection.json"
        )


    def correlate(
        self,
        alert,
        presidio_results,
        trufflehog_results
    ):


        result = {

            "alert": alert,

            "sensitive_data": {

                "pii_detection": presidio_results,

                "secret_detection": trufflehog_results

            },


            "summary": {

                "pii_count":
                    len(presidio_results),


                "secret_count":
                    len(trufflehog_results),


                "risk_level":
                    self.calculate_risk(
                        presidio_results,
                        trufflehog_results
                    )

            }

        }


        self.save(result)


        return result



    def calculate_risk(
        self,
        presidio_results,
        trufflehog_results
    ):


        if trufflehog_results:

            return "CRITICAL"


        if len(presidio_results) > 3:

            return "HIGH"


        if presidio_results:

            return "MEDIUM"


        return "LOW"



    def save(self, data):


        os.makedirs(
            "output",
            exist_ok=True
        )


        with open(
            self.output_file,
            "w",
            encoding="utf-8"
        ) as f:


            json.dump(
                data,
                f,
                indent=4,
                ensure_ascii=False
            )