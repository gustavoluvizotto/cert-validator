from cryptography import x509
import pandas as pd
import json


SHORT1 = "Signed by unknown authority"
SHORT2 = "Expired/Not yet valid"
SHORT3 = "Not authorized to sign other certificates"
SHORT4 = "Too many intermediate certificates"
SHORT5 = "Unhandled critical extension"
SHORT6 = "Other errors"
SHORT7 = "Self-signed"
SHORT8 = "Valid chain"
SHORT9 = "Invalid signature"  # under SHORT1
SHORT10 = "No valid leaf certificate"

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


def get_error_list(root_stores):
    if len(root_stores) == 0:
        return None

    error_list = []
    for _, err_dict in root_stores:
        error_list.append(err_dict['root_store_error'])

    # test that any elements are empty
    if any(not element for element in error_list):
        return []
    return error_list


def error_str2(root_stores):
    error_list = get_error_list(root_stores)
    if error_list is None:
        return SHORT10
    if error_list == []:
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


def analysis_leaves_in_chains():
    input_pdf = pd.read_parquet("shared_dir/20240709_636_cert-validator-input.parquet")
    output_pdf = pd.read_parquet("shared_dir/20240709_636_cert-validator-output.parquet")

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


def analysis_leaves_chosen():
    old_pdf = pd.read_parquet("shared_dir/old20240709_636_cert-validator-output.parquet")
    print("old method to assign leaf certificate index",
        old_pdf.groupby("leaf_cert_index").size().reset_index(name="count").sort_values("count", ascending=False)
    )
    new_pdf = pd.read_parquet("shared_dir/new20240709_636_cert-validator-output.parquet")
    print("new method to assign leaf certificate index",
        new_pdf.groupby("leaf_cert_index").size().reset_index(name="count").sort_values("count", ascending=False)
    )


def analysis_errors():
    ldap_ids = pd.read_csv("shared_dir/ldap_ids.csv")["id"].to_list()
    old_pdf = pd.read_parquet("shared_dir/old20240709_636_cert-validator-output.parquet")
    old_pdf = old_pdf[old_pdf["id"].isin(ldap_ids)]
    old_pdf["error"] = old_pdf["root_stores"].apply(error_str2)
    aggr_pdf = old_pdf.groupby("error").size().reset_index(name="count").sort_values("count", ascending=False)
    aggr_pdf["percentage"] = round(aggr_pdf["count"] / len(old_pdf) * 100, 2)
    print("old method to assign leaf certificate index\n",
        aggr_pdf
    )

    new_pdf = pd.read_parquet("shared_dir/new20240709_636_cert-validator-output.parquet")
    new_pdf = new_pdf[new_pdf["id"].isin(ldap_ids)]
    new_pdf["error"] = new_pdf["root_stores"].apply(error_str2)
    aggr_pdf = new_pdf.groupby("error").size().reset_index(name="count").sort_values("count", ascending=False)
    aggr_pdf["percentage"] = round(aggr_pdf["count"] / len(new_pdf) * 100, 2)
    print("new method to assign leaf certificate index\n",
        aggr_pdf
    )

    #print(new_pdf[new_pdf["error"] != SHORT8]["id"].to_list()[:3])  # [1460, 4935, 27129]


def all_valid_leaves():
    ldap_ids = pd.read_csv("shared_dir/ldap_ids.csv")["id"].to_list()
    new_pdf = pd.read_parquet("shared_dir/new20240709_636_cert-validator-output.parquet")
    new_pdf = new_pdf[new_pdf["id"].isin(ldap_ids)]
    new_pdf["nr_valid_leaves"] = new_pdf["all_valid_leaves_index"].map(len)
    aggr_pdf = new_pdf.groupby("nr_valid_leaves").size().reset_index(name="count").sort_values("count", ascending=False)
    valid_by_nr_leaves = aggr_pdf[aggr_pdf["nr_valid_leaves"] != 0]["count"].sum()

    print("new method all leaves that are valid\n",
          aggr_pdf
    )

    def _is_valid(root_stores):
        l = get_error_list(root_stores)
        if l == []:
            return True
        return False

    # nr of valid chain should match the nr of valid leaves==0
    new_pdf["error"] = new_pdf["root_stores"].apply(error_str2)
    aggr_pdf = new_pdf.groupby("error").size().reset_index(name="count").sort_values("count", ascending=False)
    valid_chains = aggr_pdf[aggr_pdf["error"] == SHORT8].iloc[0][1]
    new_pdf["is_valid"] = new_pdf["root_stores"].apply(_is_valid)
    aggr_pdf = new_pdf.groupby("is_valid").size().reset_index(name="count").sort_values("count", ascending=False)
    valid_leaves = aggr_pdf[aggr_pdf["is_valid"] == True].iloc[0][1]
    assert valid_chains == valid_leaves
    try:
        assert valid_chains == valid_by_nr_leaves, f"valid_chains={valid_chains} != valid_by_nr_leaves={valid_by_nr_leaves}"
    except AssertionError:
        print(f"valid_chains={valid_chains} != valid_by_nr_leaves={valid_by_nr_leaves}",
            new_pdf[(new_pdf["nr_valid_leaves"] == 0)
                    & (new_pdf["error"] == SHORT8)].sort_values("id", ascending=True)
        )

def main():
    #analysis_leaves_chosen()
    analysis_errors()
    #all_valid_leaves()
    #analysis_leaves_in_chains()


if __name__ == "__main__":
    main()
