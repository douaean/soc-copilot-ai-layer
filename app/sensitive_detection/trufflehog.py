import subprocess
import tempfile
import json
import os


class TruffleHogDetector:
    """
    Détection des secrets avec TruffleHog v3
    """

    def __init__(self):
        self.command = "/usr/local/bin/trufflehog"


    def detect(self, text: str):

        if not text:
            return []


        findings = []

        temp_file = None


        try:

            # Création fichier temporaire
            with tempfile.NamedTemporaryFile(
                mode="w",
                delete=False,
                suffix=".txt",
                encoding="utf-8"
            ) as file:

                file.write(text)

                temp_file = file.name



            command = [

                self.command,

                "filesystem",

                temp_file,

                "--json",

                "--no-update"

            ]



            result = subprocess.run(

                command,

                stdout=subprocess.PIPE,

                stderr=subprocess.PIPE,

                text=True

            )


            # Debug
            print("STDERR:")
            print(result.stderr)



            # Lecture résultat JSON

            for line in result.stdout.splitlines():

                if not line.strip():
                    continue


                try:

                    data = json.loads(line)


                    finding = {

                        "tool": "TruffleHog",

                        "detector": data.get(
                            "DetectorName"
                        ),

                        "verified": data.get(
                            "Verified"
                        ),


                        "secret": data.get(
                            "Redacted"
                        ),


                        "raw": data.get(
                            "Raw"
                        ),


                        "location": 
                            data.get(
                                "SourceMetadata",
                                {}
                            )
                            .get(
                                "Data",
                                {}
                            )
                            .get(
                                "Filesystem",
                                {}
                            ),


                        "details":
                            data.get(
                                "SecretParts"
                            )

                    }


                    findings.append(
                        finding
                    )



                except json.JSONDecodeError:

                    continue



        except Exception as e:


            findings.append({

                "tool": "TruffleHog",

                "error": str(e)

            })



        finally:


            if temp_file and os.path.exists(temp_file):

                os.remove(temp_file)



        return findings