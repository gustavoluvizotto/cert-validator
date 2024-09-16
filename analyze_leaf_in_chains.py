from cryptography import x509
import pandas as pd
import json


if False:  # too slow...
    ids_pdf = pd.DataFrame([], columns=["id", "index"])
    with open("shared_dir/log.json", mode="rt", encoding="utf-8") as f:
        for line in f.readlines():
            data = json.loads(line)
            message = data["message"]
            if "Intermediate" in message:
                ids_pdf.loc[-1] = [data["chainId"], data["index"]]
                ids_pdf.index = ids_pdf.index + 1
                ids_pdf.sort_index(inplace=True)


SHORT1 = "Signed by unknown authority"
SHORT2 = "Expired/Not yet valid"
SHORT3 = "Not authorized to sign other certificates"
SHORT4 = "Too many intermediate certificates"
SHORT5 = "Unhandled critical extension"
SHORT6 = "Other errors"
SHORT7 = "Self-signed"
SHORT8 = "Valid chain"
SHORT9 = "Invalid signature"  # under SHORT1


short_error_name_map = {
    'x509: certificate signed by unknown authority': SHORT1,
    'x509: certificate signed by unknown authority - With possible explanation': SHORT1,
    'x509: certificate has expired or is not yet valid': SHORT2,
    'x509: certificate is not authorized to sign other certificates': SHORT3,
    'x509: too many intermediates for path length constraint': SHORT4,
    'x509: unhandled critical extension': SHORT5,
    'x509: certificate signed by unknown authority (possibly because of "x509: invalid signature': SHORT9,
    'x509: certificate signed by unknown authority (possibly because of "x509': SHORT1,
    '': SHORT8
}


input_pdf = pd.read_parquet("shared_dir/20240709_636_cert-validator-input.parquet")
output_pdf = pd.read_parquet("shared_dir/20240709_636_cert-validator-output.parquet")

# below depends on jq installed and a log in the code (while building intermediate cert pool):
# log.Debug().Int32("chainId", *certChain.Id).Int("index", i).Bool("isCA", intermediate.IsCA).Str("subject.CN", intermediate.Subject.CommonName).Msg("Intermediate certificate did not set the flag")
# then run the following command:
# cat shared_dir/log.json | jq '. | select(.message | contains("Intermediate"))' | jq -r '"\(.chainId),\(.index)"' > shared_dir/ids.csv
ids_pdf = pd.read_csv("shared_dir/ids.csv")

ids = list(set(ids_pdf["id"].to_list()))
intermediate_without_isca = len(ids)
print(
    round(intermediate_without_isca/len(input_pdf) * 100, 1),
    "% of the certificates have at least one intermediate certificates without isCA"
)

filtered_output_pdf = output_pdf[output_pdf["id"].isin(ids)]
print(len(filtered_output_pdf))

filtered_input_pdf = input_pdf[input_pdf["id"].isin(ids)]
print(len(filtered_input_pdf))

id_index_dict = ids_pdf.set_index("id")["index"].to_dict()

def error_str2(root_stores):
    error_list = []
    for _, err_dict in root_stores:
        error_list.append(err_dict['root_store_error'])

    if error_list is None:
        return None
    # test that all elements are empty
    if all(not element for element in error_list):
        return SHORT8

    error_data = ""
    for error_data in error_list:
        if error_data != "":
            break

    parsed_error = ':'.join(error_data.split(":")[:3])

    error = short_error_name_map.get(parsed_error, None)
    if error is None:
        parsed_error = ':'.join(error_data.split(":")[:2])
        return short_error_name_map[parsed_error]
    return error

filtered_output_pdf["error"] = filtered_output_pdf["root_stores"].apply(error_str2)
aggr_pdf = filtered_output_pdf.groupby("error").size().reset_index(name="count")
print(aggr_pdf)
valid = aggr_pdf[aggr_pdf["error"] == SHORT8]["count"].iloc[0]
invalid = aggr_pdf[aggr_pdf["error"] != SHORT8]["count"].sum()
print(
    round(valid/len(output_pdf) * 100, 1),
    "% are valid chains that contain at least one intermediate without isCA flag or the flag is set to false"
)
print(
    round(invalid/len(output_pdf) * 100, 1),
    "% are invalid chains that contain at least one intermediate without isCA flag or the flag is set to false"
)

def has_isca_flag(pdf):
    index = id_index_dict[pdf["id"]]
    certificates = pdf["chain"]
    cert_raw = certificates[index]
    cert = x509.load_pem_x509_certificate(cert_raw.encode())
    try:
        extensions = cert.extensions
        try:
            for extension in extensions:
                if isinstance(extension.value, x509.BasicConstraints):
                    _ = extension.value.ca
                    pdf["has_isca"] = True
                    return pdf
            pdf["has_isca"] = False
            return pdf
        except x509.ExtensionNotFound:
            pdf["has_isca"] = False
            return pdf
    except ValueError:
        pdf["has_isca"] = False
        return pdf


is_ca_pdf = filtered_input_pdf.apply(has_isca_flag, axis=1)
aggr_is_ca_pdf = is_ca_pdf.groupby("has_isca").size().reset_index(name="count")
print(aggr_is_ca_pdf)

no_isca = aggr_is_ca_pdf[aggr_is_ca_pdf["has_isca"] == False]["count"].iloc[0]
print(
    round(no_isca/len(input_pdf) * 100, 1),
    "% of the chains has at least one intermediate cert without the isCA extension, and hence reported as isCa=False"
)
