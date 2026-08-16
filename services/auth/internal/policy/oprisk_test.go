package policy

import (
	"testing"
)

func TestSQLOperation(t *testing.T) {
	if SQLOperation("SELECT 1") != "" {
		t.Fatal("select")
	}
	if SQLOperation("INSERT INTO t VALUES (1)") != "sql.insert" {
		t.Fatal("insert")
	}
	if SQLOperation("DELETE FROM t") != "sql.delete" {
		t.Fatal("delete")
	}
	if SQLOperation("DROP TABLE t") != "sql.ddl" {
		t.Fatal("ddl")
	}
	if SQLOperation("DROP DATABASE prod") != "sql.drop" {
		t.Fatal("drop database")
	}
	if SQLOperation("COPY t TO STDOUT") != "sql.export" {
		t.Fatal("export")
	}
}

func TestSSHOperation(t *testing.T) {
	if SSHOperation("ls -la") != "" {
		t.Fatal("ls")
	}
	if SSHOperation("rm -rf /tmp/x") != "ssh.destructive" {
		t.Fatal("rm")
	}
	if SSHOperation("sudo -u root rm -rf /") != "ssh.destructive" {
		t.Fatal("sudo rm")
	}
	if SSHOperation("su -c 'iptables -F'") != "ssh.firewall" {
		t.Fatal("su iptables")
	}
	if SSHOperation("systemctl status nginx") != "ssh.status" {
		t.Fatal("status")
	}
	if SSHOperation("systemctl restart nginx") != "ssh.restart" {
		t.Fatal("restart")
	}
	if SSHOperation("chmod 777 /tmp/x") != "ssh.chmod777" {
		t.Fatal("chmod777")
	}
	if SSHOperation("useradd alice") != "ssh.user" {
		t.Fatal("useradd")
	}
	if SSHOperation("sudo -i") != "ssh.priv" {
		t.Fatal("sudo -i")
	}
	if SSHOperation("scp -t /tmp") != "" {
		t.Fatal("scp is DLP")
	}
}

func TestK8sOperation(t *testing.T) {
	if K8sOperation("get", "") != "" {
		t.Fatal("get")
	}
	if K8sOperation("create", "") != "k8s.write" {
		t.Fatal("create")
	}
	if K8sOperation("delete", "") != "k8s.delete" {
		t.Fatal("delete")
	}
	if K8sOperation("create", "exec") != "k8s.exec" {
		t.Fatal("exec")
	}
}

func TestHTTPOperationPoints(t *testing.T) {
	if HTTPOperation("GET") != "" {
		t.Fatal("get")
	}
	if p, f := operationPoints("http.write"); p != 20 || f != "op:http.write" {
		t.Fatalf("%d %s", p, f)
	}
	if p, f := operationPoints("http.delete"); p != 35 || f != "op:http.delete" {
		t.Fatalf("%d %s", p, f)
	}
}

func TestOperationPoints(t *testing.T) {
	if p, _ := operationPoints(""); p != 0 {
		t.Fatal("empty")
	}
	if p, f := operationPoints("sql.ddl"); p != 45 || f != "op:sql.ddl" {
		t.Fatalf("%d %s", p, f)
	}
	if p, f := operationPoints("ssh.destructive"); p != 90 || f != "op:ssh.destructive" {
		t.Fatalf("destructive %d %s", p, f)
	}
	if p, _ := operationPoints("ssh.priv"); p != 30 {
		t.Fatalf("priv %d", p)
	}
	if p, _ := operationPoints("sql.drop"); p != 100 {
		t.Fatalf("drop %d", p)
	}
}

func TestCheckOpRiskNoPoints(t *testing.T) {
	s := &Service{}
	ev, err := s.CheckOpRisk(nil, AccessCheck{Operation: "sql.select"})
	if err != nil || !ev.OK {
		t.Fatalf("read op should skip: %#v %v", ev, err)
	}
	ev, err = s.CheckOpRisk(nil, AccessCheck{Operation: SQLOperation("SELECT 1")})
	if err != nil || !ev.OK {
		t.Fatal("select")
	}
}
