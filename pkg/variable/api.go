//go:build !go1.23

package variable

type VariableQuery struct {
	FunctionName string `json:"function_name"`
	Line         int    `json:"line"`
}

type VariableDTO struct {
	Name string `json:"name"`
	Type string `json:"type"`
	ValueStr string `json:"value_str,omitempty"`
}
