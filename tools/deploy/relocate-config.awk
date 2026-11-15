# Strictly rewrite only the three fields emitted by Config::to_v2_toml.
# This is NOT a general TOML editor: unfamiliar canonical layouts fail closed.
# Prefix/final are validated safe absolute paths by install.sh; no TOML escaping
# is needed for their restricted alphabet. All other input lines stay unchanged.
function bad() { failed = 1; exit 1 }
function string_value(    c, escape, digits) {
    if (substr(text, pos++, 1) != "\"") return 0
    while (pos <= length(text)) {
        c = substr(text, pos++, 1)
        if (c == "\"") return 1
        if (c ~ /[[:cntrl:]]/) return 0
        if (c == "\\") {
            escape = substr(text, pos++, 1)
            if (escape == "u") {
                digits = substr(text, pos, 4)
                if (length(digits) != 4 || digits ~ /[^0-9A-F]/) return 0
                pos += 4
            } else if (escape != "\"" && escape != "\\" && escape != "t" && escape != "n" && escape != "r") return 0
        }
    }
    return 0
}
function scalar(value) {
    text = value; pos = 1
    return string_value() && pos == length(text) + 1
}
function roots(value) {
    text = value; pos = 1
    if (substr(text, pos++, 1) != "[") return 0
    if (substr(text, pos, 1) == "]") return pos == length(text)
    while (1) {
        if (!string_value()) return 0
        if (substr(text, pos, 1) == "]") return pos == length(text)
        if (substr(text, pos, 2) != ", ") return 0
        pos += 2
    }
}
$0 == "[paths]" {
    if (seen++) bad()
    field = 1
    print
    next
}
field == 1 {
    if (substr($0, 1, 15) != "identity_key = " || !scalar(substr($0, 16))) bad()
    print "identity_key = \"" final "/materials/identity.key\""
    field = 2
    next
}
field == 2 {
    if (substr($0, 1, 8) != "roots = " || !roots(substr($0, 9))) bad()
    print "roots = [\"" final "/materials/roots.cbor\"]"
    field = 3
    next
}
field == 3 {
    if (substr($0, 1, 12) != "state_dir = " || !scalar(substr($0, 13))) bad()
    print "state_dir = \"" prefix "/state\""
    field = 4
    next
}
field == 4 {
    if ($0 != "") bad()
    field = 5
    print
    next
}
field == 5 {
    if ($0 != "[uplink]") bad()
    field = 0
}
{ print }
END { if (failed || seen != 1 || field != 0) exit 1 }
