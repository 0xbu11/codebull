package function

import "strings"


func matchFuncName(dwarfName, funcName string, normalized bool) bool {
	if dwarfName == funcName {
		return true
	}
	if strings.HasSuffix(dwarfName, "."+funcName) {
		return true
	}
	if strings.HasSuffix(dwarfName, "/"+funcName) { // unlikely for Go but possible
		return true
	}
	if !normalized {
		return false
	}
	return normalizeFuncName(dwarfName) == normalizeFuncName(funcName)
}

func normalizeFuncName(name string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return trimmed
	}

	slash := strings.LastIndex(trimmed, "/")
	head := trimmed
	if slash >= 0 {
		head = trimmed[slash+1:]
	}

	dot := strings.Index(head, ".")
	if dot <= 0 {
		return stripTypeArgs(head)
	}

	pkg := head[:dot]
	rest := head[dot+1:]

	if isMajorVersion(pkg) && slash >= 0 {
		importPath := trimmed[:slash]
		if prev := strings.LastIndex(importPath, "/"); prev >= 0 {
			pkg = importPath[prev+1:]
		} else {
			pkg = importPath
		}
	}

	return pkg + "." + stripTypeArgs(rest)
}

func isMajorVersion(element string) bool {
	if len(element) < 2 || element[0] != 'v' {
		return false
	}
	for i := 1; i < len(element); i++ {
		if element[i] < '0' || element[i] > '9' {
			return false
		}
	}
	return true
}

func stripTypeArgs(name string) string {
	var out strings.Builder
	depth := 0
	for _, ch := range name {
		switch {
		case ch == '[':
			depth++
		case ch == ']':
			if depth > 0 {
				depth--
			}
		case depth == 0:
			out.WriteRune(ch)
		}
	}
	return out.String()
}
