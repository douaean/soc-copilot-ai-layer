from presidio_analyzer import AnalyzerEngine



class PresidioDetector:



    def __init__(self):

        self.analyzer = AnalyzerEngine()



    def detect(self, text: str):
        

        if not text:
            return []


        results = self.analyzer.analyze(

            text=text,

            language="en"

        )


        sensitive_data = []


        for result in results:

            sensitive_data.append(

                {
                    "tool": "Presidio",

                    "entity_type":
                        result.entity_type,

                    "value":
                        text[result.start:result.end],

                    "confidence":
                        round(result.score, 2),

                    "start":
                        result.start,

                    "end":
                        result.end
                }

            )


        return sensitive_data