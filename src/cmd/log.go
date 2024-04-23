package cmd

import (
	"context"
	"log/slog"
	"reflect"
	"runtime"
	"slices"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	_         slog.Handler = (*ZapHandler)(nil)
	errorKeys              = []string{"error", "err"}
	logLevels              = map[slog.Level]zapcore.Level{
		slog.LevelDebug: zap.DebugLevel,
		slog.LevelInfo:  zap.InfoLevel,
		slog.LevelWarn:  zap.WarnLevel,
		slog.LevelError: zap.ErrorLevel,
	}
)

type Option struct {
	// log level (default: debug)
	Level slog.Leveler

	// optional: zap logger (default: zap.L())
	Logger *zap.Logger

	// optional: customize json payload builder
	Converter Converter

	// optional: see slog.HandlerOptions
	AddSource   bool
	ReplaceAttr func(groups []string, a slog.Attr) slog.Attr
}

func (o Option) NewZapHandler() slog.Handler {
	if o.Level == nil {
		o.Level = slog.LevelDebug
	}

	if o.Logger == nil {
		// should be selected lazily ?
		o.Logger = zap.L()
	}

	return &ZapHandler{
		option: o,
		attrs:  []slog.Attr{},
		groups: []string{},
	}
}

type ReplaceAttrFn = func(groups []string, a slog.Attr) slog.Attr
type Converter func(addSource bool, replaceAttr func(groups []string, a slog.Attr) slog.Attr, loggerAttr []slog.Attr, groups []string, record *slog.Record) []zapcore.Field

type ZapHandler struct {
	option Option
	attrs  []slog.Attr
	groups []string
}

func (h *ZapHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.option.Level.Level()
}

func (h *ZapHandler) Handle(_ context.Context, record slog.Record) error {
	converter := defaultConverter
	if h.option.Converter != nil {
		converter = h.option.Converter
	}

	level := logLevels[record.Level]
	fields := converter(h.option.AddSource, h.option.ReplaceAttr, h.attrs, h.groups, &record)

	checked := h.option.Logger.Check(level, record.Message)
	if checked != nil {
		if h.option.AddSource {
			frame, _ := runtime.CallersFrames([]uintptr{record.PC}).Next()
			checked.Caller = zapcore.NewEntryCaller(0, frame.File, frame.Line, true)
			checked.Stack = ""
		} else {
			checked.Caller = zapcore.EntryCaller{}
			checked.Stack = ""
		}
		checked.Write(fields...)
		return nil
	}

	h.option.Logger.Log(level, record.Message, fields...)

	return nil
}

func (h *ZapHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ZapHandler{
		option: h.option,
		attrs:  appendAttrsToGroup(h.groups, h.attrs, attrs...),
		groups: h.groups,
	}
}

func (h *ZapHandler) WithGroup(name string) slog.Handler {
	return &ZapHandler{
		option: h.option,
		attrs:  h.attrs,
		groups: append(h.groups, name),
	}
}

func appendRecordAttrsToAttrs(attrs []slog.Attr, groups []string, record *slog.Record) []slog.Attr {
	output := slices.Clone(attrs)

	groups = reverse(groups)
	record.Attrs(func(attr slog.Attr) bool {
		for i := range groups {
			attr = slog.Group(groups[i], attr)
		}
		output = append(output, attr)
		return true
	})

	return output
}

func replaceAttrs(fn ReplaceAttrFn, groups []string, attrs ...slog.Attr) []slog.Attr {
	for i := range attrs {
		attr := attrs[i]
		value := attr.Value.Resolve()
		if value.Kind() == slog.KindGroup {
			attrs[i].Value = slog.GroupValue(replaceAttrs(fn, append(groups, attr.Key), value.Group()...)...)
		}
		if fn != nil {
			attrs[i] = fn(groups, attr)
		}
	}

	return attrs
}

func replaceError(attrs []slog.Attr, errorKeys ...string) []slog.Attr {
	replaceAttr := func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) > 1 {
			return a
		}

		for i := range errorKeys {
			if a.Key == errorKeys[i] {
				if err, ok := a.Value.Any().(error); ok {
					return slog.Any(a.Key, formatError(err))
				}
			}
		}
		return a
	}
	return replaceAttrs(replaceAttr, []string{}, attrs...)
}

func attrsToStringAnyMap(attrs ...slog.Attr) map[string]any {
	output := map[string]any{}

	attrsByKey := groupValuesByKey(attrs)
	for k, values := range attrsByKey {
		v := mergeAttrValues(values...)
		if v.Kind() == slog.KindGroup {
			output[k] = attrsToStringAnyMap(v.Group()...)
			continue
		}

		output[k] = v.Any()
	}

	return output
}

func formatError(err error) map[string]any {
	return map[string]any{
		"kind":  reflect.TypeOf(err).String(),
		"error": err.Error(),
		"stack": nil, // @TODO
	}
}

func appendAttrsToGroup(groups []string, actualAttrs []slog.Attr, newAttrs ...slog.Attr) []slog.Attr {
	actualAttrs = slices.Clone(actualAttrs)

	if len(groups) == 0 {
		return uniqAttrs(append(actualAttrs, newAttrs...))
	}

	for i := range actualAttrs {
		attr := actualAttrs[i]
		if attr.Key == groups[0] && attr.Value.Kind() == slog.KindGroup {
			actualAttrs[i] = slog.Group(groups[0], toAnySlice(appendAttrsToGroup(groups[1:], attr.Value.Group(), newAttrs...))...)
			return actualAttrs
		}
	}

	return uniqAttrs(append(actualAttrs, slog.Group(groups[0], toAnySlice(appendAttrsToGroup(groups[1:], []slog.Attr{}, newAttrs...))...)))
}

func uniqAttrs(attrs []slog.Attr) []slog.Attr {
	return uniqByLast(attrs, func(item slog.Attr) string {
		return item.Key
	})
}

func uniqByLast[T any, U comparable](collection []T, iteratee func(item T) U) []T {
	result := make([]T, 0, len(collection))
	seen := make(map[U]int, len(collection))
	seenIndex := 0

	for _, item := range collection {
		key := iteratee(item)

		if index, ok := seen[key]; ok {
			result[index] = item
			continue
		}

		seen[key] = seenIndex
		seenIndex++
		result = append(result, item)
	}

	return result
}

func groupValuesByKey(attrs []slog.Attr) map[string][]slog.Value {
	result := map[string][]slog.Value{}

	for _, item := range attrs {
		key := item.Key
		result[key] = append(result[key], item.Value)
	}

	return result
}

func mergeAttrValues(values ...slog.Value) slog.Value {
	v := values[0]

	for i := 1; i < len(values); i++ {
		if v.Kind() != slog.KindGroup || values[i].Kind() != slog.KindGroup {
			v = values[i]
			continue
		}

		v = slog.GroupValue(append(v.Group(), values[i].Group()...)...)
	}

	return v
}

func defaultConverter(addSource bool, replaceAttr func(groups []string, a slog.Attr) slog.Attr, loggerAttr []slog.Attr, groups []string, record *slog.Record) []zapcore.Field {
	attrs := appendRecordAttrsToAttrs(loggerAttr, groups, record)
	attrs = replaceError(attrs, errorKeys...)
	attrs = replaceAttrs(replaceAttr, []string{}, attrs...)

	// handler formatter
	fields := attrsToStringAnyMap(attrs...)

	output := make([]zapcore.Field, 0, len(attrs))
	for k, v := range fields {
		output = append(output, zap.Any(k, v))
	}

	return output
}

func toAnySlice[T any](collection []T) []any {
	result := make([]any, len(collection))
	for i, item := range collection {
		result[i] = item
	}
	return result
}

func reverse[T any](collection []T) []T {
	length := len(collection)
	half := length / 2

	for i := 0; i < half; i = i + 1 {
		j := length - 1 - i
		collection[i], collection[j] = collection[j], collection[i]
	}

	return collection
}
