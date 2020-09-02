// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/quay/claircore/internal/vulnstore (interfaces: Updater)

// Package vulnstore is a generated GoMock package.
package vulnstore

import (
	context "context"
	gomock "github.com/golang/mock/gomock"
	uuid "github.com/google/uuid"
	claircore "github.com/quay/claircore"
	driver "github.com/quay/claircore/libvuln/driver"
	reflect "reflect"
)

// MockUpdater is a mock of Updater interface
type MockUpdater struct {
	ctrl     *gomock.Controller
	recorder *MockUpdaterMockRecorder
}

// MockUpdaterMockRecorder is the mock recorder for MockUpdater
type MockUpdaterMockRecorder struct {
	mock *MockUpdater
}

// NewMockUpdater creates a new mock instance
func NewMockUpdater(ctrl *gomock.Controller) *MockUpdater {
	mock := &MockUpdater{ctrl: ctrl}
	mock.recorder = &MockUpdaterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockUpdater) EXPECT() *MockUpdaterMockRecorder {
	return m.recorder
}

// DeleteUpdateOperations mocks base method
func (m *MockUpdater) DeleteUpdateOperations(arg0 context.Context, arg1 ...uuid.UUID) error {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0}
	for _, a := range arg1 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "DeleteUpdateOperations", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteUpdateOperations indicates an expected call of DeleteUpdateOperations
func (mr *MockUpdaterMockRecorder) DeleteUpdateOperations(arg0 interface{}, arg1 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0}, arg1...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteUpdateOperations", reflect.TypeOf((*MockUpdater)(nil).DeleteUpdateOperations), varargs...)
}

// GetLatestUpdateRef mocks base method
func (m *MockUpdater) GetLatestUpdateRef(arg0 context.Context) (uuid.UUID, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetLatestUpdateRef", arg0)
	ret0, _ := ret[0].(uuid.UUID)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetLatestUpdateRef indicates an expected call of GetLatestUpdateRef
func (mr *MockUpdaterMockRecorder) GetLatestUpdateRef(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLatestUpdateRef", reflect.TypeOf((*MockUpdater)(nil).GetLatestUpdateRef), arg0)
}

// GetLatestUpdateRefs mocks base method
func (m *MockUpdater) GetLatestUpdateRefs(arg0 context.Context) (map[string]uuid.UUID, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetLatestUpdateRefs", arg0)
	ret0, _ := ret[0].(map[string]uuid.UUID)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetLatestUpdateRefs indicates an expected call of GetLatestUpdateRefs
func (mr *MockUpdaterMockRecorder) GetLatestUpdateRefs(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLatestUpdateRefs", reflect.TypeOf((*MockUpdater)(nil).GetLatestUpdateRefs), arg0)
}

// GetUpdateDiff mocks base method
func (m *MockUpdater) GetUpdateDiff(arg0 context.Context, arg1, arg2 uuid.UUID) (*driver.UpdateDiff, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUpdateDiff", arg0, arg1, arg2)
	ret0, _ := ret[0].(*driver.UpdateDiff)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUpdateDiff indicates an expected call of GetUpdateDiff
func (mr *MockUpdaterMockRecorder) GetUpdateDiff(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUpdateDiff", reflect.TypeOf((*MockUpdater)(nil).GetUpdateDiff), arg0, arg1, arg2)
}

// GetUpdateOperations mocks base method
func (m *MockUpdater) GetUpdateOperations(arg0 context.Context, arg1 ...string) (map[string][]driver.UpdateOperation, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0}
	for _, a := range arg1 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetUpdateOperations", varargs...)
	ret0, _ := ret[0].(map[string][]driver.UpdateOperation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUpdateOperations indicates an expected call of GetUpdateOperations
func (mr *MockUpdaterMockRecorder) GetUpdateOperations(arg0 interface{}, arg1 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0}, arg1...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUpdateOperations", reflect.TypeOf((*MockUpdater)(nil).GetUpdateOperations), varargs...)
}

// UpdateVulnerabilities mocks base method
func (m *MockUpdater) UpdateVulnerabilities(arg0 context.Context, arg1 string, arg2 driver.Fingerprint, arg3 []*claircore.Vulnerability) (uuid.UUID, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateVulnerabilities", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(uuid.UUID)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateVulnerabilities indicates an expected call of UpdateVulnerabilities
func (mr *MockUpdaterMockRecorder) UpdateVulnerabilities(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateVulnerabilities", reflect.TypeOf((*MockUpdater)(nil).UpdateVulnerabilities), arg0, arg1, arg2, arg3)
}
