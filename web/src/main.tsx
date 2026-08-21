import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AppLayout, HomePage } from "./App";
import { AuthProvider } from "./auth";
import { I18nProvider } from "./i18n";
import { SessionTabsProvider } from "./sessionTabs";
import { AccessRequestsPage } from "./pages/AccessRequestsPage";
import { AssetEditPage } from "./pages/AssetEditPage";
import { AssetsPage } from "./pages/AssetsPage";
import { AuditPage } from "./pages/AuditPage";
import { LoginPage } from "./pages/LoginPage";
import { SessionReplayPage } from "./pages/SessionReplayPage";
import { WatchPage } from "./pages/WatchPage";
import { SessionsPage } from "./pages/SessionsPage";
import { SetupPage } from "./pages/SetupPage";
import { TerminalPage } from "./pages/TerminalPage";
import { ConfigPage } from "./pages/ConfigPage";
import { DesktopPage } from "./pages/DesktopPage";
import { DiscoveryPage } from "./pages/DiscoveryPage";
import { AnalyticsPage } from "./pages/AnalyticsPage";
import { CompliancePage } from "./pages/CompliancePage";
import { JeaPage } from "./pages/JeaPage";
import { AttackSimPage } from "./pages/AttackSimPage";
import { SqlConsolePage } from "./pages/SqlConsolePage";
import { AppSessionPage } from "./pages/AppSessionPage";
import { K8sSessionPage } from "./pages/K8sSessionPage";
import { Tn3270Page } from "./pages/Tn3270Page";
import { CitrixPage } from "./pages/CitrixPage";
import { ForensicPage } from "./pages/ForensicPage";
import { GroupsPage } from "./pages/GroupsPage";
import { UserEditPage } from "./pages/UserEditPage";
import { PasswordSetsPage } from "./pages/PasswordSetsPage";
import { ProfilePage } from "./pages/ProfilePage";
import { UsersPage } from "./pages/UsersPage";
import "./styles.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <I18nProvider>
    <AuthProvider>
      <BrowserRouter>
        <SessionTabsProvider>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/setup" element={<SetupPage />} />
            <Route element={<AppLayout />}>
              <Route path="/" element={<HomePage />} />
              <Route path="/assets" element={<AssetsPage />} />
              <Route path="/assets/:id" element={<AssetEditPage />} />
              <Route path="/password-sets" element={<PasswordSetsPage />} />
              <Route path="/discovery" element={<DiscoveryPage />} />
              <Route path="/analytics" element={<AnalyticsPage />} />
              <Route path="/compliance" element={<CompliancePage />} />
              <Route path="/jea" element={<JeaPage />} />
              <Route path="/attack-sim" element={<AttackSimPage />} />
              <Route path="/access-requests" element={<AccessRequestsPage />} />
              <Route path="/sessions" element={<SessionsPage />} />
              <Route path="/forensic" element={<ForensicPage />} />
              <Route path="/sessions/:id/terminal" element={<TerminalPage />} />
              <Route path="/sessions/:id/sql" element={<SqlConsolePage />} />
              <Route path="/sessions/:id/app" element={<AppSessionPage />} />
              <Route path="/sessions/:id/k8s" element={<K8sSessionPage />} />
              <Route path="/sessions/:id/tn3270" element={<Tn3270Page />} />
              <Route path="/sessions/:id/citrix" element={<CitrixPage />} />
              <Route path="/sessions/:id/desktop" element={<DesktopPage />} />
              <Route path="/sessions/:id/replay" element={<SessionReplayPage />} />
              <Route path="/sessions/:id/watch" element={<WatchPage />} />
              <Route path="/profile" element={<ProfilePage />} />
              <Route path="/users" element={<UsersPage />} />
              <Route path="/users/:id" element={<UserEditPage />} />
              <Route path="/groups" element={<GroupsPage />} />
              <Route path="/audit" element={<AuditPage />} />
              <Route path="/config" element={<ConfigPage />} />
            </Route>
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </SessionTabsProvider>
      </BrowserRouter>
    </AuthProvider>
    </I18nProvider>
  </StrictMode>,
);
