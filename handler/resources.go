package handler

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"agentdna-ratelimit-auth/db"
)

const (
	listPageSize    = 10
	listMaxPageSize = 100
)

// listPage reads a 1-based page and its size from pageKey / sizeKey.
// The size is capped so one request cannot pull a whole list.
func listPage(c *gin.Context, pageKey, sizeKey string) (page, pageSize int) {
	page = 1
	if p, err := strconv.Atoi(c.Query(pageKey)); err == nil && p > 0 {
		page = p
	}
	pageSize = listPageSize
	if ps, err := strconv.Atoi(c.Query(sizeKey)); err == nil && ps > 0 {
		pageSize = min(ps, listMaxPageSize)
	}
	return page, pageSize
}

func pageInfo(total, page, pageSize int) gin.H {
	return gin.H{
		"total":      total,
		"page":       page,
		"pageSize":   pageSize,
		"totalPages": (total + pageSize - 1) / pageSize,
	}
}

// ResourcesList handles GET /dashboard/v1/resources-list?page=&pageSize=
// &trustStatus=: every resource, most-used first. trustStatus, when given,
// keeps only resources with that trust status (Unreviewed, Flagged, Trusted).
func (h *Handler) ResourcesList(c *gin.Context) {
	page, pageSize := listPage(c, "page", "pageSize")
	trustStatus := strings.TrimSpace(c.Query("trustStatus"))
	if trustStatus != "" && !db.ValidResourceTrustStatuses[trustStatus] {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "trustStatus must be one of Unreviewed, Flagged, Trusted"})
		return
	}

	total, err := h.db.CountResources(trustStatus)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to count resources: %v", err)})
		return
	}
	resources, err := h.db.ListResources(trustStatus, pageSize, (page-1)*pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch resources: %v", err)})
		return
	}

	list := make([]gin.H, 0, len(resources))
	for _, r := range resources {
		list = append(list, gin.H{
			"resourceID":      r.ID,
			"name":            r.Name,
			"url":             r.ID,
			"trustStatus":     r.TrustStatus,
			"intentCount":     r.IntentCount,
			"credentialCount": r.CredentialCount,
		})
	}
	data := pageInfo(total, page, pageSize)
	data["trustStatus"] = trustStatus
	data["resourcesList"] = list
	c.JSON(http.StatusOK, Response{Status: true, Data: data})
}

// ResourceInfo handles GET /dashboard/v1/resource-info?resourceID=
// &intentsPage=&intentsPageSize=&credentialsPage=&credentialsPageSize=:
// one resource with a page of the intents that reached it and a page of
// the credentials they used. The two lists page independently.
func (h *Handler) ResourceInfo(c *gin.Context) {
	resourceID := c.Query("resourceID")
	if resourceID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "resourceID is required"})
		return
	}

	resource, err := h.db.GetResource(resourceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch resource: %v", err)})
		return
	}
	if resource == nil {
		c.JSON(http.StatusNotFound, Response{Status: false, Message: "resource not found"})
		return
	}

	intentsPage, intentsPageSize := listPage(c, "intentsPage", "intentsPageSize")
	intents, err := h.db.GetResourceIntents(resourceID, intentsPageSize, (intentsPage-1)*intentsPageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch resource intents: %v", err)})
		return
	}
	credentialsPage, credentialsPageSize := listPage(c, "credentialsPage", "credentialsPageSize")
	credentials, err := h.db.GetResourceCredentials(resourceID, credentialsPageSize, (credentialsPage-1)*credentialsPageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch resource credentials: %v", err)})
		return
	}

	intentIDs := make([]string, 0, len(intents))
	for _, i := range intents {
		intentIDs = append(intentIDs, i.IntentID)
	}
	warnings := h.intentWarnings(intentIDs)
	intentList := make([]gin.H, 0, len(intents))
	for _, i := range intents {
		var startedAt any
		if i.StartedAt.Valid {
			startedAt = i.StartedAt.Time
		}
		credentialIDs := i.CredentialIDs
		if credentialIDs == nil {
			credentialIDs = []string{}
		}
		urls := i.URLs
		if urls == nil {
			urls = []string{}
		}
		intentList = append(intentList, gin.H{
			"intentID":       i.IntentID,
			"initiatorDID":   i.InitiatorDID,
			"initiatorName":  i.InitiatorName,
			"status":         i.Status,
			"reviewStatus":   i.ReviewStatus,
			"flowType":       i.FlowType,
			"threatDetected": i.ThreatDetected,
			"warnings":       warnings[i.IntentID],
			"startedAt":      startedAt,
			"credentialIDs":  credentialIDs,
			"urls":           urls,
		})
	}
	credentialList := make([]gin.H, 0, len(credentials))
	for _, cr := range credentials {
		credentialList = append(credentialList, gin.H{
			"credentialID": cr.CredentialID,
			"authMethod":   cr.AuthMethod,
			"intentCount":  cr.IntentCount,
			"status":       cr.Status,
		})
	}

	intentsData := pageInfo(resource.IntentCount, intentsPage, intentsPageSize)
	intentsData["list"] = intentList
	credentialsData := pageInfo(resource.CredentialCount, credentialsPage, credentialsPageSize)
	credentialsData["list"] = credentialList

	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{
		"resourceID":      resource.ID,
		"name":            resource.Name,
		"url":             resource.ID,
		"trustStatus":     resource.TrustStatus,
		"intentCount":     resource.IntentCount,
		"credentialCount": resource.CredentialCount,
		"intents":         intentsData,
		"credentials":     credentialsData,
	}})
}

// UpdateResourceTrustStatus handles POST /dashboard/v1/update-resource-trust-status
// {resourceID, trustStatus}: sets a resource's trust status to Unreviewed,
// Flagged or Trusted. Admins only.
func (h *Handler) UpdateResourceTrustStatus(c *gin.Context) {
	if !c.GetBool(CtxIsAdmin) {
		c.JSON(http.StatusForbidden, Response{Status: false, Message: "admin access required"})
		return
	}

	var req struct {
		ResourceID  string `json:"resourceID"`
		TrustStatus string `json:"trustStatus"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "invalid request body"})
		return
	}
	req.ResourceID = strings.TrimSpace(req.ResourceID)
	req.TrustStatus = strings.TrimSpace(req.TrustStatus)
	if req.ResourceID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "resourceID is required"})
		return
	}
	if !db.ValidResourceTrustStatuses[req.TrustStatus] {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "trustStatus must be one of Unreviewed, Flagged, Trusted"})
		return
	}

	resource, err := h.db.SetResourceTrustStatus(req.ResourceID, req.TrustStatus)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to update resource trust status: %v", err)})
		return
	}
	if resource == nil {
		c.JSON(http.StatusNotFound, Response{Status: false, Message: "resource not found"})
		return
	}

	updatedBy := c.GetString(CtxEmail)
	if updatedBy == "" {
		updatedBy = c.GetString(CtxDID)
	}
	log.Printf("[resources] trust_status resource_id=%q trust_status=%s by=%q", resource.ID, resource.TrustStatus, updatedBy)
	h.recomputeWarnings(nil, resource.ID, "")

	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{
		"resourceID":  resource.ID,
		"name":        resource.Name,
		"url":         resource.ID,
		"trustStatus": resource.TrustStatus,
	}})
}
