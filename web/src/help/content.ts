import type { Lang } from "../i18n/catalog";

export type LText = Record<Lang, string>;

export type HelpAction = {
  name: LText;
  desc: LText;
};

export type HelpTopic = {
  id: string;
  /** Section grouping for TOC */
  group: "start" | "work" | "security" | "admin" | "sessions";
  title: LText;
  summary: LText;
  /** Deep paragraphs */
  body: LText[];
  actions?: HelpAction[];
  /** Related topic ids */
  related?: string[];
  /** In-app route */
  href?: string;
  /** Optional two-column guide (need → where) */
  table?: {
    headers: [LText, LText];
    rows: [LText, LText][];
  };
};

const t = (ru: string, en: string, kk: string): LText => ({ ru, en, kk });

export const HELP_GROUPS: { id: HelpTopic["group"]; title: LText }[] = [
  { id: "start", title: t("Начало работы", "Getting started", "Бастау") },
  { id: "work", title: t("Работа", "Work", "Жұмыс") },
  { id: "sessions", title: t("Сессии и инструменты", "Sessions & tools", "Сеанстар мен құралдар") },
  { id: "security", title: t("Безопасность", "Security", "Қауіпсіздік") },
  { id: "admin", title: t("Администрирование", "Administration", "Әкімшілік") },
];

export const HELP_TOPICS: HelpTopic[] = [
  {
    id: "overview",
    group: "start",
    href: "/",
    title: t("Обзор", "Overview", "Шолу"),
    summary: t(
      "Домашняя страница: у администратора PAM — дашборд с аналитикой и графиками за 24 часа; у остальных — вход в работу.",
      "Home: PAM admins see a 24h analytics dashboard with charts; others get a work entry point.",
      "Басты бет: PAM әкімшісіне 24 сағаттық аналитика мен графиктер; қалғандарына жұмыс кірісі.",
    ),
    body: [
      t(
        "Дашборд на «Обзоре» виден только администратору PAM (роль admin / право users.write) и требует audit.read. Карточки, график входов, протоколы, топ пользователей/активов и аномалии — за 24 часа. Полный отчёт — раздел Аналитика.",
        "The Overview dashboard is for PAM admins only (admin role / users.write) and needs audit.read. Cards, login chart, protocols, top users/assets, and anomalies cover 24 hours. Full report: Analytics.",
        "«Шолу» дашборды тек PAM әкімшісіне (admin / users.write) және audit.read қажет. 24 сағат: карточкалар, кіру графигі, хаттамалар, топ, аномалиялар. Толық есеп — Аналитика.",
      ),
      t(
        "Уведомления (колокольчик в шапке сайдбара) показывают очередь запросов и событий. «Прочитать все» снимает непрочитанные; клик по уведомлению открывает Запросы.",
        "The bell in the sidebar shows request/event inbox. “Mark all read” clears unread; clicking an item opens Requests.",
        "Сайдбардағы қоңырау сұрау/оқиға кезегін көрсетеді. «Барлығын оқу» оқылмағандарды өшіреді; басу Сұрауларды ашады.",
      ),
    ],
    related: ["assets", "sessions", "requests", "analytics"],
  },
  {
    id: "nav",
    group: "start",
    title: t("Меню и группы", "Menu & groups", "Мәзір және топтар"),
    summary: t(
      "Сайдбар сгруппирован: Работа, Безопасность, Администрирование. Пустые группы скрыты по правам.",
      "Sidebar groups: Work, Security, Administration. Empty groups are hidden by permissions.",
      "Сайдбар топтары: Жұмыс, Қауіпсіздік, Әкімшілік. Бос топтар құқық бойынша жасырылады.",
    ),
    body: [
      t(
        "Группы раскрываются аккордеоном. Состояние запоминается в браузере. Группа текущего раздела открывается автоматически. Бейдж на «Запросы» и на свёрнутой группе «Работа» показывает число ожидающих согласований.",
        "Groups expand as accordions and persist in the browser. The group for the current route opens automatically. A badge on Requests (and on a collapsed Work group) shows pending approvals.",
        "Топтар аккордеонмен ашылады және браузерде сақталады. Ағымдағы бөлім тобы автоматты ашылады. Сұраулар бейджі (және жабық Жұмыс тобында) күтудегі мақұлдау санын көрсетеді.",
      ),
      t(
        "Пункты без соответствующего права (например jea.read) не отображаются. Профиль и выход — в нижней части сайдбара.",
        "Items without the matching permission (e.g. jea.read) are hidden. Profile and sign-out live at the bottom of the sidebar.",
        "Қажетті құқықсыз пункттер (мыс. jea.read) көрсетілмейді. Профиль мен шығу — сайдбардың төменінде.",
      ),
    ],
    related: ["overview", "profile"],
  },
  {
    id: "assets",
    group: "work",
    href: "/assets",
    title: t("Активы", "Assets", "Активтер"),
    summary: t(
      "Каталог целевых систем (SSH, RDP, БД, HTTPS, kubectl, TN3270, Citrix). Отсюда создают активы и инициируют подключения.",
      "Catalog of targets (SSH, RDP, DB, HTTPS, kubectl, TN3270, Citrix). Create assets and start connections here.",
      "Мақсат жүйелер каталогы (SSH, RDP, ДҚ, HTTPS, kubectl, TN3270, Citrix). Осыдан актив құрылады және қосылым басталады.",
    ),
    body: [
      t(
        "Список для operator — только назначенные активы (ACL пользователя/роли/группы или владелец). Вкладка «Каталог» показывает остальные для запроса JIT. Администратор (assets.write / assets.acl) видит весь инвентарь.",
        "Operators see only assigned assets (user/role/group ACL or ownership). Catalog lists the rest for a JIT request. Admins (assets.write / assets.acl) see the full inventory.",
        "operator үшін тізім — тек тағайындалған активтер (ACL немесе иесі). «Каталог» қойындысы JIT сұрауға арналған. Әкімші барлық инвентарды көреді.",
      ),
      t(
        "Список фильтруется и ищется по имени/адресу. «Создать» требует assets.write и свободный слот, если лицензия SKU assets/both (SKU users — безлимит активов).",
        "The list is searchable by name/address. Create needs assets.write and a free slot when the license SKU is assets/both (users SKU does not cap assets).",
        "Тізім аты/мекенжайы бойынша ізделеді. Құруға assets.write және бос лицензия слоты керек (hard_blocked құруды тыяды).",
      ),
      t(
        "Вкладки «Активные» и «Архив»: сначала актив уходит в архив; из архива — восстановление или безвозвратное удаление (история сессий сохраняется).",
        "Active and Archive tabs: first move an asset to the archive; from the archive restore or permanently delete (session history is kept).",
        "«Белсенді» және «Мұрағат» қойындылары: алдымен мұрағат; мұрағаттан қалпына келтіру немесе толығымен жою (сеанс тарихы сақталады).",
      ),
      t(
        "«Подключить» / «Открыть SSH» / SQL / kubectl создаёт PAM-сессию с учётом ACL, JIT и Access Policy. Если нужен тикет или reason — форма запросит их до connect. При four-eyes сессия ждёт супервайзера.",
        "Connect / Open SSH / SQL / kubectl creates a PAM session under ACL, JIT, and Access Policy. Ticket/reason prompts appear before connect when required. With four-eyes the session waits for a supervisor.",
        "Қосу / SSH / SQL / kubectl ACL, JIT және Access Policy бойынша PAM-сеанс құрады. Тикет/reason қажет болса — connect алдында сұралады. Four-eyes кезінде супервайзер күтіледі.",
      ),
      t(
        "SSH «Файл подключения» скачивает OpenSSH config для шлюза :2222 (User = логин KeepPAM, RemoteCommand = актив/учётка). Секрет цели в файл не попадает — см. docs/ssh-connection-file.txt.",
        "SSH Connection file downloads an OpenSSH config for gateway :2222 (User = KeepPAM login, RemoteCommand = asset/account). Target vault secret is not in the file — see docs/ssh-connection-file.txt.",
        "SSH «Қосылым файлы» :2222 шлюзі үшін OpenSSH config жүктейді. Мақсат құпиясы файлда жоқ — docs/ssh-connection-file.txt.",
      ),
      t(
        "Кнопка «Native-клиент» (SSH/RDP): Connection File + Launcher (.cmd/.sh). RDP — mstsc + .rdp; запись replay через rdp-jump (.guac). SSH — OpenSSH config + ssh. Документация: docs/native-client.txt, docs/native-rdp.txt.",
        "Native client (SSH/RDP): Connection File + Launcher (.cmd/.sh). RDP — mstsc + .rdp; replay via rdp-jump (.guac). SSH — OpenSSH config + ssh. See docs/native-client.txt, docs/native-rdp.txt.",
        "«Native-клиент» (SSH/RDP): Connection File + Launcher. docs/native-client.txt, docs/native-rdp.txt.",
      ),
      t(
        "Для RDP можно выбрать разрешение экрана перед подключением. Буфер обмена RDP управляется политикой (см. JEA → Policy → RDP clipboard), а не кнопкой на списке активов.",
        "For RDP you can pick screen resolution before connect. RDP clipboard is controlled by policy (JEA → Policy → RDP clipboard), not by a button on the assets list.",
        "RDP үшін қосылмас бұрын экран өлшемін таңдауға болады. RDP буфері саясатпен басқарылады (JEA → Policy → RDP clipboard).",
      ),
    ],
    actions: [
      {
        name: t("Создать / Новый актив", "Create / New asset", "Құру / Жаңа актив"),
        desc: t("Открывает карточку нового актива.", "Opens a blank asset editor.", "Жаңа актив карточкасын ашады."),
      },
      {
        name: t("Открыть", "Open", "Ашу"),
        desc: t("Карточка актива: сеть, учётки, ACL, JIT, break-glass.", "Asset card: network, accounts, ACL, JIT, break-glass.", "Актив карточкасы: желі, тіркелгілер, ACL, JIT, break-glass."),
      },
      {
        name: t("Подключить", "Connect", "Қосу"),
        desc: t("Старт сессии под выбранной учёткой.", "Starts a session with the selected account.", "Таңдалған тіркелгімен сеанс бастайды."),
      },
      {
        name: t("Запросить JIT-доступ", "Request JIT access", "JIT сұрау"),
        desc: t("Создаёт запрос в очереди Запросы (этапы/кворум по настройке актива).", "Creates a request in Requests (stages/quorum per asset settings).", "Сұраулар кезегінде сұрау құрады (кезең/кворум актив баптауына сай)."),
      },
    ],
    related: ["asset-edit", "requests", "sessions", "discovery", "password-sets", "jea", "desktop"],
  },
  {
    id: "asset-edit",
    group: "work",
    href: "/assets",
    title: t("Карточка актива", "Asset editor", "Актив карточкасы"),
    summary: t(
      "Полная настройка цели: протокол, учётки, ротация, ACL, JIT, four-eyes, RemoteApp, ephemeral DB.",
      "Full target setup: protocol, accounts, rotation, ACL, JIT, four-eyes, RemoteApp, ephemeral DB.",
      "Толық баптау: протокол, тіркелгілер, ротация, ACL, JIT, four-eyes, RemoteApp, ephemeral DB.",
    ),
    body: [
      t(
        "Учётные записи хранят секреты в vault. Rotate генерирует новый пароль и пушит на цель (если настроено). Checkout / Reveal выдают секрет оператору с аудитом; dual-control checkout требует второго одобрения в Запросах. Checkout не обязателен для обычного PAM-подключения — connect использует vault напрямую.",
        "Accounts keep secrets in the vault. Rotate generates and pushes a new password when configured. Checkout / Reveal expose the secret to an operator with audit; dual-control checkout needs a second approval in Requests. Checkout is not required for normal PAM connect — connect uses the vault directly.",
        "Тіркелгілер құпияны vault-та сақтайды. Rotate жаңа құпия сөз жасайды. Checkout / Reveal операторға құпияны аудитпен береді; dual-control екінші мақұлдауды Сұрауларда талап етеді. Қалыпты PAM қосылымға Checkout міндетті емес.",
      ),
      t(
        "ACL (Выдать / Изменить / Отозвать) привязывает группу/роль к активу и Access Policy. Policy ужесточает требования (тикет, CIDR, RDP redirection) относительно ACL. Tag ACL в JEA добавляет доступ по тегам актива.",
        "ACL (Grant / Edit / Revoke) binds a group/role to the asset and an Access Policy. Policy only tightens requirements (ticket, CIDR, RDP redirection) relative to the ACL. JEA Tag ACL adds access by asset tags.",
        "ACL (Бері / Өзгерт / Қайтар) топ/рөлді активке және Access Policy-ге байлайды. Policy ACL-ге қатысты талапты тек күшейтеді. JEA Tag ACL тег бойынша қолжетімділік қосады.",
      ),
      t(
        "Break-glass: экстренный доступ с reason ≥ 20 символов, пишется в audit как critical. Four-eyes: сессия pending до разрешения супервайзера (не себя); таймаут ожидания около 15 минут.",
        "Break-glass: emergency access with reason ≥ 20 characters, audited as critical. Four-eyes: session stays pending until a supervisor (not yourself) authorizes; wait timeout ~15 minutes.",
        "Break-glass: reason ≥ 20 таңба, audit-та critical. Four-eyes: супервайзер (өзіңіз емес) рұқсат еткенше pending; күту ~15 мин.",
      ),
    ],
    actions: [
      {
        name: t("В архив / Восстановить / Удалить навсегда", "Archive / Restore / Delete forever", "Мұрағат / Қалпына / Толығымен жою"),
        desc: t(
          "Сначала актив уходит в архив (без подключений). Из архива можно восстановить или удалить навсегда; история сессий сохраняется.",
          "First move the asset to the archive (no connections). From the archive you can restore or permanently delete; session history is kept.",
          "Алдымен актив мұрағатқа өтеді (қосылымсыз). Мұрағаттан қалпына келтіру немесе толығымен жоюға болады; сеанс тарихы сақталады.",
        ),
      },
      {
        name: t("Ротировать", "Rotate", "Ротация"),
        desc: t("Смена секрета на цели и в vault.", "Changes the secret on the target and in the vault.", "Мақсатта және vault-та құпияны өзгертеді."),
      },
      {
        name: t("Checkout / Reveal / Check-in", "Checkout / Reveal / Check-in", "Checkout / Reveal / Check-in"),
        desc: t("Временная выдача секрета оператору.", "Temporary secret hand-out to an operator.", "Операторға уақытша құпия беру."),
      },
      {
        name: t("Сбросить host key", "Reset host key", "Host key қалпына"),
        desc: t("Сброс known_hosts при смене ключа SSH-сервера.", "Clears known_hosts after SSH host key change.", "SSH host key өзгергенде known_hosts тазалайды."),
      },
    ],
    related: ["assets", "requests", "jea", "password-sets", "config"],
  },
  {
    id: "discovery",
    group: "work",
    href: "/discovery",
    title: t("Discovery", "Discovery", "Discovery"),
    summary: t(
      "Сканирование сети и каталогов для поиска кандидатов в активы и учётки.",
      "Network and directory scans to find asset/account candidates.",
      "Актив/тіркелгі кандидаттарын табу үшін желі және каталог сканері.",
    ),
    body: [
      t(
        "Типы сканов: сеть (хосты/порты), учётки SSH, AD privileged, Windows WinRM/SAM. После скана кандидаты импортируются в Активы при праве assets.write.",
        "Scan types: network (hosts/ports), SSH accounts, AD privileged, Windows WinRM/SAM. Candidates import into Assets with assets.write.",
        "Скан түрлері: желі, SSH тіркелгілері, AD privileged, Windows WinRM/SAM. Кандидаттар assets.write кезінде Активтерге импортталады.",
      ),
      t(
        "Для AD/LDAP сканов нужны корректные настройки каталога в Конфигурации. Discovery не заменяет ACL — после импорта выдайте доступ группам.",
        "AD/LDAP scans need correct directory settings in Configuration. Discovery does not replace ACL — grant group access after import.",
        "AD/LDAP сканына Конфигурациядағы каталог баптауы керек. Discovery ACL-ді алмастырмайды — импорттан кейін топтарға қолжетімділік беріңіз.",
      ),
    ],
    actions: [
      {
        name: t("Новый скан / Запустить", "New scan / Run", "Жаңа скан / Іске қосу"),
        desc: t("Создаёт задание discovery.run.", "Creates a discovery.run job.", "discovery.run тапсырмасын құрады."),
      },
      {
        name: t("Импорт", "Import", "Импорт"),
        desc: t("Превращает кандидата в актив/учётку.", "Turns a candidate into an asset/account.", "Кандидатты актив/тіркелгіге айналдырады."),
      },
    ],
    related: ["assets", "config"],
  },
  {
    id: "password-sets",
    group: "work",
    href: "/password-sets",
    title: t("Синхронизация паролей", "Password sync", "Құпия сөз синхрондауы"),
    summary: t(
      "Один логический пароль на несколько учёток (unix + AD + DB) с согласованной ротацией.",
      "One logical password across accounts (unix + AD + DB) with coordinated rotation.",
      "Бір логикалық құпия сөз бірнеше тіркелгіге (unix + AD + DB).",
    ),
    body: [
      t(
        "Набор объединяет password-учётки. «Rotate all» генерирует секрет и пушит участникам в порядке sync (сначала host, потом AD — или наоборот). directory_last удобен, если AD сразу инвалидирует старый пароль.",
        "A set groups password accounts. Rotate all generates a secret and pushes members in sync order (hosts then AD — or reverse). directory_last helps when AD invalidates the old password immediately.",
        "Жинақ password-тіркелгілерді біріктіреді. Rotate all құпияны sync ретімен жібереді. directory_last AD ескі құпияны бірден жарамсыз еткенде ыңғайлы.",
      ),
    ],
    actions: [
      {
        name: t("Новый набор / Сохранить", "New set / Save", "Жаңа жинақ / Сақтау"),
        desc: t("CRUD набора и состава участников.", "CRUD for the set and members.", "Жинақ пен мүшелер CRUD."),
      },
      {
        name: t("Rotate all", "Rotate all", "Rotate all"),
        desc: t("Ротация секрета на всех участниках.", "Rotates the secret on all members.", "Барлық мүшелерде құпияны ротациялайды."),
      },
    ],
    related: ["assets", "asset-edit", "requests"],
  },
  {
    id: "requests",
    group: "work",
    href: "/access-requests",
    title: t("Запросы доступа", "Access requests", "Қолжетімділік сұраулары"),
    summary: t(
      "Очередь JIT, break-glass, checkout секретов, супервизия four-eyes и операционных step-up.",
      "Queue for JIT, break-glass, secret checkout, four-eyes supervision, and operational step-up.",
      "JIT, break-glass, checkout, four-eyes және операциялық step-up кезегі.",
    ),
    body: [
      t(
        "Разделы страницы разделяют типы очередей: JIT (один/два этапа, кворум N/M), ИБ-одобрение, супервайзер сессии, операции внутри сессии, break-glass, dual-control checkout. Бейдж в меню — сумма ожидающих пунктов для вашей роли.",
        "Page sections split queues: JIT (one/two stage, quorum N/M), security approval, session supervisor, in-session operations, break-glass, dual-control checkout. The nav badge sums items waiting for your role.",
        "Бет бөлімдері кезектерді бөледі: JIT, ИБ, супервайзер, сеанс іші операциялар, break-glass, dual-control checkout. Мәзір бейджі рөліңізге күтетіндер қосындысы.",
      ),
      t(
        "Одобряющий не должен быть заявителем там, где включён dual-control. Свою four-eyes сессию супервизить нельзя. Отмена доступна заявителю для своих pending-запросов.",
        "Approvers must not be the requester where dual-control applies. You cannot supervise your own four-eyes session. Requesters can cancel their own pending requests.",
        "Dual-control кезінде мақұлдаушы өтініш беруші болмауы керек. Өз four-eyes сеансыңызды супервизиялауға болмайды.",
      ),
    ],
    actions: [
      {
        name: t("Одобрить / Отклонить", "Approve / Deny", "Мақұлдау / Қабылдамау"),
        desc: t("Решение по выбранному запросу.", "Decision on the selected request.", "Таңдалған сұрау бойынша шешім."),
      },
      {
        name: t("Одобрить (N/M)", "Approve (N/M)", "Мақұлдау (N/M)"),
        desc: t("Голос в кворуме JIT.", "A vote in JIT quorum.", "JIT кворумындағы дауыс."),
      },
      {
        name: t("Разрешить супервайзера", "Authorize supervisor", "Супервайзер рұқсаты"),
        desc: t("Four-eyes: пуск ожидающей сессии.", "Four-eyes: release a waiting session.", "Four-eyes: күтіп тұрған сеансты жіберу."),
      },
    ],
    related: ["assets", "sessions", "audit", "jea"],
  },
  {
    id: "sessions",
    group: "work",
    href: "/sessions",
    title: t("Сессии", "Sessions", "Сеанстар"),
    summary: t(
      "Список онлайн и исторических PAM-сессий: наблюдение, kill, replay, ожидание супервайзера.",
      "Online and historical PAM sessions: watch, kill, replay, supervisor wait.",
      "Онлайн және тарихи PAM-сеанстар: бақылау, kill, replay, супервайзер күтуі.",
    ),
    body: [
      t(
        "Вкладки Онлайн / Все / События. Политика (JEA Access Policy) фиксируется snapshot’ом в момент создания сессии — позднее изменение Policy не меняет уже открытую сессию.",
        "Tabs: Online / All / Events. Access Policy is snapshotted at session create — later Policy edits do not affect an already open session.",
        "Қойындылар: Онлайн / Барлығы / Оқиғалар. Access Policy сеанс құрылғанда snapshot болады — кейінгі өзгеріс ашық сеансқа әсер етпейді.",
      ),
      t(
        "Открытые сессии держатся во вкладках сверху (Session tab bar). Переключение на другие страницы не должно рвать SSH/RDP — сессия остаётся в keep-alive хосте. Закрытие вкладки с «завершить» убивает сессию на сервере.",
        "Open sessions stay in the top Session tab bar. Navigating away should not kill SSH/RDP — sessions live in the keep-alive host. Closing a tab with end terminates the server session.",
        "Ашық сеанстар жоғарғы Session tab bar-да қалады. Басқа бетке өту SSH/RDP-ны үзбеуі керек. «Аяқтау»мен қойындыны жабу сервердегі сеансты өлтіреді.",
      ),
    ],
    actions: [
      {
        name: t("Наблюдать", "Watch", "Бақылау"),
        desc: t("Live view-only (SSH поток; RDP без полного видео в этом режиме).", "Live view-only (SSH stream; RDP without full video in this mode).", "Live тек қарау (SSH ағын; RDP толық бейнесіз)."),
      },
      {
        name: t("Завершить", "End", "Аяқтау"),
        desc: t("Принудительный kill сессии.", "Force-kills the session.", "Сеансты мәжбүрлі аяқтайды."),
      },
      {
        name: t("Replay / Скачать", "Replay / Download", "Replay / Жүктеу"),
        desc: t("Воспроизведение записи и файлы (SCP/RDP capture).", "Playback recording and files (SCP/RDP capture).", "Жазбаны ойнату және файлдар."),
      },
    ],
    related: ["forensic", "terminal", "desktop", "watch", "replay", "requests"],
  },
  {
    id: "terminal",
    group: "sessions",
    title: t("SSH / Telnet терминал", "SSH / Telnet terminal", "SSH / Telnet терминал"),
    summary: t(
      "xterm-сессия: ввод, буфер обмена, вкладки keep-alive, JEA line-buffer при политике команд.",
      "xterm session: input, clipboard, keep-alive tabs, JEA line-buffer under command policy.",
      "xterm сеансы: енгізу, буфер, keep-alive қойындылар, команда саясатында JEA line-buffer.",
    ),
    body: [
      t(
        "Кнопки «Копировать» / «Вставить» и Ctrl+C (с выделением) / Ctrl+V. ПКМ вставляет последний известный текст вкладки (на HTTP браузер часто блокирует чтение OS-буфера по ПКМ — сначала Ctrl+V).",
        "Copy / Paste buttons and Ctrl+C (with selection) / Ctrl+V. Right-click pastes the tab’s last known text (on HTTP browsers often block OS clipboard read on right-click — use Ctrl+V first).",
        "Көшіру / Қою және Ctrl+C (белгілеумен) / Ctrl+V. Оң батырма қойындының соңғы мәтінін қояды (HTTP-та ПКМ жиі бұғатталады — алдымен Ctrl+V).",
      ),
      t(
        "При активном пакете команд JEA ввод буферизуется построчно: стрелки двигают курсор по строке локально (не должны печатать «[D[C»). Запрещённые команды отклоняются с сообщением KeepPAM JEA.",
        "With an active JEA command pack, input is line-buffered: arrows move the cursor locally (must not print “[D[C”). Denied commands show a KeepPAM JEA message.",
        "JEA команда пакеті қосулы кезде енгізу жолмен буферленеді: көрсеткілер курсорды жергілікті жылжытады («[D[C» басылмауы керек).",
      ),
      t(
        "Если ввод «пропал», проверьте статус: при обрыве WebSocket появится сообщение о потере соединения — закройте вкладку и откройте сессию заново. Клиент шлёт keepalive ping.",
        "If typing stops, check status: a lost WebSocket shows a disconnect message — close the tab and reopen the session. The client sends keepalive pings.",
        "Енгізу тоқтаса, күйді қараңыз: WebSocket үзілсе хабар шығады — қойындыны жауып сеансты қайта ашыңыз.",
      ),
    ],
    actions: [
      {
        name: t("Копировать / Вставить", "Copy / Paste", "Көшіру / Қою"),
        desc: t("Работа с буфером терминала.", "Terminal clipboard helpers.", "Терминал буфері."),
      },
      {
        name: t("Закрыть", "Close", "Жабу"),
        desc: t("Закрывает UI-вкладку и завершает сессию.", "Closes the UI tab and ends the session.", "UI қойындысын жауып сеансты аяқтайды."),
      },
    ],
    related: ["sessions", "jea", "desktop"],
  },
  {
    id: "desktop",
    group: "sessions",
    title: t("RDP / VNC (Desktop)", "RDP / VNC (Desktop)", "RDP / VNC (Desktop)"),
    summary: t(
      "HTML5 Guacamole: экран, клавиатура, мышь, буфер по политике rdp_clipboard.",
      "HTML5 Guacamole: screen, keyboard, mouse, clipboard via rdp_clipboard policy.",
      "HTML5 Guacamole: экран, пернетақта, тінтуір, rdp_clipboard саясатымен буфер.",
    ),
    body: [
      t(
        "По умолчанию DLP-strict: RDP clipboard / drive / printer выключены. Включите «RDP clipboard» в JEA → Policy у Access Policy, привязанной к ACL, затем откройте сессию заново (нужен новый snapshot).",
        "Default is DLP-strict: RDP clipboard / drive / printer off. Enable “RDP clipboard” in JEA → Policy on the Access Policy bound via ACL, then open a new session (needs a fresh snapshot).",
        "Әдепкі DLP-strict: RDP clipboard / drive / printer өшірулі. JEA → Policy ішінде «RDP clipboard» қосып, сеансты қайта ашыңыз.",
      ),
      t(
        "При включённом clipboard: Ctrl+V / кнопка «Вставить» синхронизируют текст на remote. ПКМ на Windows оставляет системное контекстное меню (не перехватывается). Статус в тулбаре показывает, включён ли буфер политикой.",
        "With clipboard on: Ctrl+V / Paste sync text to the remote. Right-click on Windows keeps the system context menu (not hijacked). Toolbar status shows whether policy enabled clipboard.",
        "Буфер қосулы кезде: Ctrl+V / Қою мәтінді remote-қа синхрондайды. Windows ПКМ жүйе мәзірін қалдырады. Тулбар саясат күйін көрсетеді.",
      ),
      t(
        "rdp_drive / rdp_printer / rdp_native — отдельные флаги той же Policy. Захват файлов из drive/clipboard staging — при file_transfer=audit|capture (см. документацию RDP file capture).",
        "rdp_drive / rdp_printer / rdp_native are separate flags on the same Policy. File capture from drive/clipboard staging needs file_transfer=audit|capture.",
        "rdp_drive / rdp_printer / rdp_native — сол Policy-дің бөлек жалаулары. Файлды ұстау file_transfer=audit|capture кезінде.",
      ),
    ],
    actions: [
      {
        name: t("Вставить", "Paste", "Қою"),
        desc: t("Локальный буфер → remote (если политика разрешает).", "Local clipboard → remote (if policy allows).", "Жергілікті буфер → remote (саясат рұқсат етсе)."),
      },
      {
        name: t("Закрыть", "Close", "Жабу"),
        desc: t("Отключение Guacamole и завершение сессии.", "Disconnects Guacamole and ends the session.", "Guacamole үзіп сеансты аяқтайды."),
      },
    ],
    related: ["jea", "sessions", "assets", "terminal"],
  },
  {
    id: "watch",
    group: "sessions",
    title: t("Наблюдение (Watch)", "Live watch", "Бақылау (Watch)"),
    summary: t(
      "Просмотр чужой активной сессии без управления (кроме kill при праве supervise).",
      "View another active session without control (except kill with supervise).",
      "Басқа белсенді сеансты басқарусыз қарау (supervise кезінде kill қоспағанда).",
    ),
    body: [
      t(
        "SSH: live поток терминала (только чтение). RDP/VNC/isolated browser в этом режиме обычно без полной видеотрансляции — доступны статус и принудительное завершение. Закрытие страницы Watch не завершает сессию оператора.",
        "SSH: live terminal stream (read-only). RDP/VNC/isolated browser usually lack full video here — status and force-end remain. Closing Watch does not end the operator’s session.",
        "SSH: live терминал (тек оқу). RDP/VNC әдетте толық бейнесіз — күй және мәжбүрлі аяқтау бар. Watch жабу оператор сеансын аяқтамайды.",
      ),
    ],
    related: ["sessions", "replay", "requests"],
  },
  {
    id: "replay",
    group: "sessions",
    title: t("Replay записи", "Session replay", "Жазбаны қайта ойнату"),
    summary: t(
      "Воспроизведение asciicast / Guacamole recording, OCR, файлы сессии, экспорт.",
      "Playback of asciicast / Guacamole recording, OCR, session files, export.",
      "asciicast / Guacamole жазбасын ойнату, OCR, сеанс файлдары, экспорт.",
    ),
    body: [
      t(
        "Управление: Play/Pause, перемотка. Для RDP — WebM/MP4 (если guacenc обработал запись), OCR по кадрам при настройке политики. Файлы SCP/SFTP и RDP drive/clipboard — в списке файлов сессии при capture. Если включён ИИ-помощник — после индекса появляется сводка (клик по пункту перематывает запись).",
        "Controls: Play/Pause, seek. For RDP — WebM/MP4 when guacenc processed the recording, OCR frames when policy enables it. SCP/SFTP and RDP drive/clipboard files appear when capture is on. With AI copilot enabled, a summary appears after indexing (click a bullet to seek).",
        "Басқару: Play/Pause. RDP үшін WebM/MP4 (guacenc өңдесе), OCR саясат бойынша. SCP/SFTP және RDP файлдары capture кезінде. ИИ қосулы болса, индекс кейін жиынтық шығады.",
      ),
    ],
    related: ["sessions", "forensic", "jea", "ai-copilot"],
  },
  {
    id: "forensic",
    group: "security",
    href: "/forensic",
    title: t("Расследование", "Investigation", "Тергеу"),
    summary: t(
      "Поиск по timeline аудита и индексным событиям сессий (команды, SQL, файлы, процессы).",
      "Search across audit timeline and indexed session events (commands, SQL, files, processes).",
      "Аудит timeline және сеанс индекс оқиғалары бойынша іздеу.",
    ),
    body: [
      t(
        "Фильтры: пользователь, окно времени, источник (аудит|сессии), текст, файл, процесс. CSV-экспорт. Ссылка «Сессия» ведёт к карточке/replay. RDP-видео как таковое в индекс не попадает — опирайтесь на OCR/метаданные и аудит.",
        "Filters: user, time window, source (audit|sessions), text, file, process. CSV export. Session links open the card/replay. Raw RDP video is not indexed — use OCR/metadata and audit.",
        "Сүзгілер: пайдаланушы, уақыт, дереккөз, мәтін, файл, процесс. CSV. Сеанс сілтемесі card/replay ашады. RDP бейнесі индекске кірмейді.",
      ),
    ],
    actions: [
      {
        name: t("Показать / CSV", "Show / CSV", "Көрсету / CSV"),
        desc: t("Запрос выборки и выгрузка.", "Runs the query and exports.", "Сұрау және экспорт."),
      },
    ],
    related: ["sessions", "audit", "replay", "analytics"],
  },
  {
    id: "jea",
    group: "security",
    href: "/jea",
    title: t("JEA и Access Policy", "JEA & Access Policy", "JEA және Access Policy"),
    summary: t(
      "Пакеты команд/SQL/HTTP/объектов и Access Policy (риск, DLP, RDP redirection, OCR).",
      "Command/SQL/HTTP/object packs and Access Policy (risk, DLP, RDP redirection, OCR).",
      "Команда/SQL/HTTP/объект пакеттері және Access Policy.",
    ),
    body: [
      t(
        "Вкладки: SSH commands, SQL, HTTP URL ACL, App objects, Policy, Теги активов. Пакеты привязываются через Access Policy и ACL актива (или Tag ACL). Try/parse проверяет команду до сохранения.",
        "Tabs: SSH commands, SQL, HTTP URL ACL, App objects, Policy, Asset tags. Packs bind via Access Policy and asset ACL (or Tag ACL). Try/parse checks a command before save.",
        "Қойындылар: SSH, SQL, HTTP, Objects, Policy, Тегтер. Пакеттер Access Policy және ACL арқылы байланады.",
      ),
      t(
        "Policy: ticket/reason, CIDR, страны, устройства, namespaces, egress, PII/NLP DLP, file_transfer, OCR (интервал / каждый кадр / live / SSH-вывод), max_risk / risk_action (deny, require_approval, require_mfa, terminate, lock_account), флаги rdp_clipboard|drive|printer|native. Default clipboard off (DLP-strict). Изменения действуют на новые сессии.",
        "Policy: ticket/reason, CIDR, countries, devices, namespaces, egress, PII/NLP DLP, file_transfer, OCR (interval / every frame / live / SSH stdout), max_risk / risk_action (deny, require_approval, require_mfa, terminate, lock_account), rdp_* flags. Clipboard defaults off (DLP-strict). Changes apply to new sessions.",
        "Policy: ticket/reason, CIDR, DLP, file_transfer, OCR (интервал / әр кадр / live / SSH), max_risk (deny/require_approval/require_mfa/terminate/lock_account), rdp_* жалаулары. Clipboard әдепкі өшірулі. Өзгеріс жаңа сеанстарға әсер етеді.",
      ),
    ],
    actions: [
      {
        name: t("Создать / Сохранить пакет", "Create / Save pack", "Пакет құру / сақтау"),
        desc: t("CRUD правил allow/deny.", "CRUD for allow/deny rules.", "allow/deny ережелерінің CRUD."),
      },
      {
        name: t("Парсить (try)", "Parse (try)", "Талдау (try)"),
        desc: t("Превью решения по строке команды/SQL.", "Preview decision for a command/SQL string.", "Команда/SQL жолы бойынша шешім превьюі."),
      },
      {
        name: t("RDP clipboard (checkbox)", "RDP clipboard (checkbox)", "RDP clipboard (checkbox)"),
        desc: t("Разрешает HTML5 clipboard в Desktop-сессиях.", "Allows HTML5 clipboard in Desktop sessions.", "Desktop сеанстарында HTML5 буферін рұқсат етеді."),
      },
    ],
    related: ["desktop", "assets", "attack-sim", "requests"],
  },
  {
    id: "attack-sim",
    group: "security",
    href: "/attack-sim",
    title: t("Attack sim", "Attack sim", "Attack sim"),
    summary: t(
      "Прогон сценариев против контролей PAM (не атака на целевые хосты).",
      "Runs scenarios against PAM controls (does not attack target hosts).",
      "PAM бақылауларына қарсы сценарийлер (мақсат хосттарға шабуыл емес).",
    ),
    body: [
      t(
        "Запуск suite создаёт прогон с результатами pass/fail по сценариям (JEA deny, policy gates и т.д.). Используйте после изменения пакетов Policy/команд.",
        "Running a suite creates a run with per-scenario pass/fail (JEA deny, policy gates, etc.). Use after changing Policy/command packs.",
        "Suite іске қосу pass/fail нәтижелі прогон құрады. Policy/команда пакеттерін өзгерткеннен кейін қолданыңыз.",
      ),
    ],
    related: ["jea", "audit"],
  },
  {
    id: "analytics",
    group: "security",
    href: "/analytics",
    title: t("Аналитика", "Analytics", "Талдау"),
    summary: t(
      "Дашборд метрик: сессии, входы, JIT, ротации, аномалии, UEBA.",
      "Metrics dashboard: sessions, logins, JIT, rotations, anomalies, UEBA.",
      "Метрика дашборды: сеанстар, кірулер, JIT, ротация, аномалия, UEBA.",
    ),
    body: [
      t(
        "Окна 24ч/7д и фильтр severity. Данные опираются на audit и агрегаты; SIEM/UEBA-ML настраиваются в Конфигурации.",
        "Windows 24h/7d and severity filter. Data comes from audit and aggregates; SIEM/UEBA-ML are configured under Configuration.",
        "24с/7к терезелері және severity сүзгісі. Дерек audit пен агрегаттардан; SIEM/UEBA-ML Конфигурацияда.",
      ),
    ],
    related: ["audit", "config", "sessions"],
  },
  {
    id: "compliance",
    group: "security",
    href: "/compliance",
    title: t("Compliance", "Compliance", "Compliance"),
    summary: t(
      "Retention, legal hold, SBOM, отчёты, DR drill, eIDAS PDF при наличии сертификата.",
      "Retention, legal hold, SBOM, reports, DR drill, eIDAS PDF when a certificate is present.",
      "Retention, legal hold, SBOM, есептер, DR drill, сертификат болса eIDAS PDF.",
    ),
    body: [
      t(
        "Audit events append-only. Purge/retention подчиняются legal hold. Отчёты могут не включать OCR RDP. PDF квалифицированной подписи — раздел eIDAS в Конфигурации.",
        "Audit events are append-only. Purge/retention respect legal hold. Reports may omit RDP OCR. Qualified PDF signing uses the eIDAS section in Configuration.",
        "Audit оқиғалары append-only. Purge/retention legal hold-қа бағынады. PDF — Конфигурациядағы eIDAS.",
      ),
    ],
    related: ["audit", "config", "forensic"],
  },
  {
    id: "audit",
    group: "security",
    href: "/audit",
    title: t("Аудит", "Audit", "Аудит"),
    summary: t(
      "Журнал действий с hash-chain: проверка целостности и подпись хвоста.",
      "Action log with hash-chain: integrity verify and tail signing.",
      "Hash-chain әрекет журналы: тұтастықты тексеру және құйрықты қолтаңбалау.",
    ),
    body: [
      t(
        "«Проверить цепочку» валидирует hash-связь записей. «Подписать хвост» фиксирует конец цепочки (ключ из конфигурации/KMS). Поиск и пагинация по action/resource.",
        "Verify chain validates hash links. Sign tail seals the chain end (key from config/KMS). Search and pagination by action/resource.",
        "Тізбекті тексеру hash байланысын валидтейді. Құйрықты қолтаңбалау тізбекті бекітеді.",
      ),
    ],
    related: ["analytics", "compliance", "forensic", "requests"],
  },
  {
    id: "users",
    group: "admin",
    href: "/users",
    title: t("Пользователи", "Users", "Пайдаланушылар"),
    summary: t(
      "Учётные записи PAM: роли admin / operator / auditor / owner / security, группы, MFA.",
      "PAM accounts: admin / operator / auditor / owner / security roles, groups, MFA.",
      "PAM тіркелгілері: admin / operator / auditor / owner / security рөлдері, топтар, MFA.",
    ),
    body: [
      t(
        "Создание локальных пользователей, назначение одной роли (права платформы), групп (WHO в ACL) и тегов ABAC. Сброс пароля и MFA — отдельные права. Карточка открывается из списка или Профиля. При создании по умолчанию ставится operator: каталог активов пустой, пока админ не выдаст ACL или не одобрит запрос из вкладки «Каталог».",
        "Create local users, assign one role (platform permissions), groups (ACL WHO), and ABAC tags. Password/MFA reset need specific permissions. User cards open from the list or Profile. New users default to operator: the asset list stays empty until an admin grants ACL or approves a Catalog request.",
        "Жергілікті пайдаланушы құру, бір рөл (платформа құқықтары), топтар (ACL WHO) және ABAC тегтер. Құпия сөз/MFA — бөлек құқықтар. Жаңа пайдаланушы әдепкі operator: актив тізімі бос, әкімші ACL бергенше немесе «Каталог» сұрауын мақұлдағанша.",
      ),
      t(
        "Роль — права на функции PAM (меню, Connect, Approve). Группа — не роль: ею выдают доступ к активам в ACL. Не назначайте несколько платформенных ролей сразу, особенно не смешивайте owner с admin/operator/auditor/security: тогда фильтр «только свои активы» отключается. RADIUS/IdP Filter-Id: admin, operator, auditor, security, owner (или keeppam-…).",
        "A role is platform capability (menu, Connect, Approve). A group is not a role: it is ACL WHO for assets. Do not stack platform roles, especially owner with admin/operator/auditor/security — that turns off the “own assets only” filter. RADIUS/IdP Filter-Id: admin, operator, auditor, security, owner (or keeppam-…).",
        "Рөл — PAM функция құқықтары. Топ — рөл емес: ACL-де активке қолжетімділік. owner-ді admin/operator/auditor/security-мен араластырмаңыз — «тек өз активтері» сүзгісі өшеді.",
      ),
    ],
    table: {
      headers: [
        t("Роль", "Role", "Рөл"),
        t("Что можно и чего нельзя", "What they can and cannot do", "Не істей алады / істей алмайды"),
      ],
      rows: [
        [
          t("admin", "admin", "admin"),
          t(
            "Полный доступ к PAM (пользователи, активы, настройки, Connect с обходом ACL — пишется session.admin_bypass). Не выдавайте эту роль рядовым операторам.",
            "Full PAM access (users, assets, settings, Connect with ACL bypass — audited as session.admin_bypass). Do not give this to day-to-day operators.",
            "PAM-ға толық қолжетімділік. Қатардағы операторға бермеңіз.",
          ),
        ],
        [
          t("operator", "operator", "operator"),
          t(
            "Подключение и запрос JIT. Видит и подключается только к активам, которые назначил админ (ACL на пользователя/роль/группу) или одобрил по запросу. Без Connect ко всему каталогу.",
            "Connect and JIT request. Sees and connects only to assets an admin assigned (user/role/group ACL) or approved after a request. No Connect to the whole catalog.",
            "Қосылу және JIT сұрау. Тек әкімші тағайындаған немесе мақұлдаған активтер. Бүкіл каталогқа Connect жоқ.",
          ),
        ],
        [
          t("auditor", "auditor", "auditor"),
          t(
            "Только чтение: пользователи, активы, сессии, forensic, файлы SCP/SFTP, аудит, аналитика, compliance, discovery. Нет Connect, нет ACL, нет создания пользователей и настроек.",
            "Read-only: users, assets, sessions, forensic, SCP/SFTP files, audit, analytics, compliance, discovery. No Connect, no ACL, no user create, no settings.",
            "Тек оқу: пайдаланушылар, активтер, сеанстар, forensic, аудит, compliance. Connect, ACL, пайдаланушы құру жоқ.",
          ),
        ],
        [
          t("owner", "owner", "owner"),
          t(
            "Владелец своих систем: список и сессии только где assets.owner_user_id = этот пользователь (поле на карточке актива). Может править актив, ACL, ходить на цель без ACL, согласовывать JIT (этап manager). Не смешивать с другими ролями. Нет users.write и настроек PAM.",
            "Owner of assigned systems: list and sessions only where assets.owner_user_id is this user (set on the asset card). Can edit the asset, ACL, connect without ACL, approve JIT (manager stage). Do not combine with other roles. No users.write or PAM settings.",
            "Өз жүйелерінің иесі: тек owner_user_id = осы пайдаланушы. Актив/ACL/сеанс өз хосттарында. Басқа рөлдермен араластырмаңыз.",
          ),
        ],
        [
          t("security", "security", "security"),
          t(
            "ИБ: второй этап JIT (access.approve.security, после руководителя) и супервайзер «четыре глаза» (sessions.supervise). Не админ PAM и не оператор на все хосты. Не давайте users.write (иначе обход ACL при Connect) и access.approve (чтобы один человек не закрывал оба этапа).",
            "InfoSec: second JIT stage (access.approve.security, after the manager) and four-eyes supervisor (sessions.supervise). Not a PAM admin and not an operator for every host. Do not grant users.write (ACL bypass on Connect) or access.approve (so one person cannot close both JIT stages).",
            "АҚ: JIT екінші кезеңі және four-eyes супервайзер. PAM әкімшісі емес. users.write және access.approve бермеңіз.",
          ),
        ],
      ],
    },
    actions: [
      {
        name: t("Создать", "Create", "Құру"),
        desc: t(
          "Локальный пользователь. Роль operator — без активов, пока нет ACL или одобренного запроса.",
          "Local user. The operator role has no assets until ACL or an approved request.",
          "Жергілікті пайдаланушы. operator рөлінде актив жоқ, ACL немесе мақұлданған сұрау болғанша.",
        ),
      },
      {
        name: t("Карточка пользователя", "User card", "Пайдаланушы карточкасы"),
        desc: t(
          "Роли, группы, теги ABAC, MFA, SSH-ключи, статус.",
          "Roles, groups, ABAC tags, MFA, SSH keys, status.",
          "Рөлдер, топтар, ABAC тегтер, MFA, SSH кілттер, күй.",
        ),
      },
      {
        name: t("Выдать доступ к активу", "Grant asset access", "Активке қолжетімділік беру"),
        desc: t(
          "Карточка актива → ACL (пользователь / роль / группа) или одобрить запрос в Запросах. Для owner — поле «Владелец актива».",
          "Asset card → ACL (user / role / group) or approve a request in Requests. For owner — the Asset owner field.",
          "Актив карточкасы → ACL немесе Сұрауларды мақұлдау. owner үшін — «Актив иесі» өрісі.",
        ),
      },
    ],
    related: ["groups", "profile", "assets", "requests"],
  },
  {
    id: "groups",
    group: "admin",
    href: "/groups",
    title: t("Группы", "Groups", "Топтар"),
    summary: t(
      "Иерархия групп для ACL активов и наследования.",
      "Group hierarchy for asset ACL and inheritance.",
      "Актив ACL және мұрагерлік үшін топ иерархиясы.",
    ),
    body: [
      t(
        "Дочерние группы наследуют доступ родителя, если так настроено ACL. Участники задаются на карточке группы. Связка с Tag ACL в JEA — для доступа по тегам активов.",
        "Child groups inherit parent access when ACL is configured that way. Members are set on the group card. Combine with JEA Tag ACL for tag-based asset access.",
        "Бала топтар ата-ана қолжетімділігін мұралай алады. Мүшелер топ карточкасында. JEA Tag ACL-мен тег бойынша қолжетімділік.",
      ),
    ],
    related: ["users", "assets", "jea"],
  },
  {
    id: "config",
    group: "admin",
    href: "/config",
    title: t("Конфигурация", "Configuration", "Баптау"),
    summary: t(
      "Лицензия, IdP (OIDC/SAML/LDAP/RADIUS/SCIM), SIEM, ITSM, Firewall PAM, NAC, eIDAS, UEBA, уведомления.",
      "License, IdP (OIDC/SAML/LDAP/RADIUS/SCIM), SIEM, ITSM, Firewall PAM, NAC, eIDAS, UEBA, notifications.",
      "Лицензия, IdP, SIEM, ITSM, Firewall PAM, NAC, eIDAS, UEBA, хабарламалар.",
    ),
    body: [
      t(
        "Раздел требует settings.write. Лицензия .lic: SKU assets / users (concurrent) / both. Auth-провайдеры определяют вход на /login. SIEM/UEBA кормят Аналитику; eIDAS — PDF в Compliance; Firewall/NAC — сетевой контур активов.",
        "Requires settings.write. The .lic license SKU is assets, users (concurrent), or both. Auth providers drive /login. SIEM/UEBA feed Analytics; eIDAS feeds Compliance PDFs; Firewall/NAC cover the asset network edge.",
        "settings.write керек. .lic лицензиясы актив шегін анықтайды. Auth провайдерлері /login-ді басқарады.",
      ),
    ],
    related: ["compliance", "analytics", "discovery", "users", "ai-copilot"],
  },
  {
    id: "ai-copilot",
    group: "admin",
    href: "/config",
    title: t("ИИ-помощник", "AI copilot", "ИИ көмекшісі"),
    summary: t(
      "On-prem сводка сессии, поиск по смыслу, карточка согласующего. Не в live deny и не автоapprove.",
      "On-prem session summary, semantic search, approver brief. Not on the live deny path and not auto-approve.",
      "On-prem сеанс жиынтығы, мағыналық іздеу. Live deny және автоapprove жоқ.",
    ),
    body: [
      t(
        "Отдельного пункта «ИИ» в меню нет. Сначала включите помощник: Конфигурация → ссылка «ИИ-помощник». Режим on, выберите бесплатную модель (Mock или Ollama: Llama 3.2 / Qwen 2.5 / Mistral / Gemma 2 / Phi-3). Endpoint для Ollama: http://ai-runtime:11434, кнопка «Скачать в Ollama». Без включения сводки отвечают 503. Лицензия: флаг ai_copilot. Облачные free-tier (Groq, OpenRouter) — только при KEEPPAM_AI_ALLOW_EXTERNAL=1.",
        "There is no sidebar item named AI. Enable it first: Configuration → “AI copilot”. Mode on, pick a free model (Mock or Ollama: Llama 3.2 / Qwen 2.5 / Mistral / Gemma 2 / Phi-3). Ollama endpoint: http://ai-runtime:11434, then “Pull into Ollama”. Otherwise summaries return 503. License flag: ai_copilot. Cloud free tiers (Groq, OpenRouter) only with KEEPPAM_AI_ALLOW_EXTERNAL=1.",
        "Мәзірде «ИИ» пункті жоқ. Конфигурация → «ИИ-помощник». Режим on, тегін модель (Mock немесе Ollama). Ollama: http://ai-runtime:11434. Лицензия: ai_copilot.",
      ),
      t(
        "Модель не вызывается из SSH PTY, JEA MatchCommand и live deny и не нажимает Approve сама. Записи сессий в облачный LLM не уходят.",
        "The model is not called from SSH PTY, JEA MatchCommand, or live deny, and it never clicks Approve. Session recordings are not sent to a cloud LLM.",
        "Модель SSH PTY / JEA / live deny ішінде шақырылмайды және Approve баспайды. Сеанс жазбалары бұлттық LLM-ге жіберілмейді.",
      ),
    ],
    table: {
      headers: [
        t("Что нужно", "What you need", "Не қажет"),
        t("Куда идти", "Where to go", "Қайда бару"),
      ],
      rows: [
        [
          t("Сводка сессии", "Session summary", "Сеанс жиынтығы"),
          t("Сессии → открыть запись (replay) → блок «Сводка ИИ»", "Sessions → open recording (replay) → “AI summary”", "Сеанстар → replay → «Сводка ИИ»"),
        ],
        [
          t("Поиск по смыслу", "Semantic search", "Мағыналық іздеу"),
          t("Сессии → чекбокс «По смыслу»", "Sessions → “Semantic” checkbox", "Сеанстар → «По смыслу»"),
        ],
        [
          t("Контекст для согласования", "Approver context", "Келісу контексті"),
          t("Запросы → кнопка «Контекст» у JIT / four-eyes / команды", "Requests → “Context” on JIT / four-eyes / command", "Сұраулар → «Контекст» (JIT / four-eyes / команда)"),
        ],
        [
          t("Черновик политики", "Policy draft", "Саясат жобасы"),
          t("JEA → форма «Черновик политики (ИИ)»", "JEA → “Policy draft (AI)”", "JEA → «Черновик политики (ИИ)»"),
        ],
        [
          t("Вопрос по справке", "Help Q&A", "Анықтама сұрағы"),
          t("Справка → поле «Спросить» вверху", "Help → “Ask” at the top", "Анықтама → «Спросить»"),
        ],
        [
          t("Проза отчёта", "Report narrative", "Есеп мәтіні"),
          t("Compliance → галка «Проза ИИ» при генерации", "Compliance → “AI narrative” when generating", "Compliance → «Проза ИИ»"),
        ],
        [
          t("Пояснение риска", "Risk explanation", "Тәуекел түсіндірмесі"),
          t("Аналитика → у аномалии с id сессии кнопка «Пояснение риска»", "Analytics → “Risk explanation” on an anomaly with a session id", "Талдау → «Пояснение риска» (сеанс id бар аномалия)"),
        ],
      ],
    },
    related: ["config", "sessions", "replay", "requests", "jea", "compliance", "analytics"],
  },
  {
    id: "profile",
    group: "admin",
    href: "/profile",
    title: t("Профиль", "Profile", "Профиль"),
    summary: t(
      "Ваши роли, группы, MFA и ссылка на карточку пользователя.",
      "Your roles, groups, MFA, and a link to the user card.",
      "Рөлдеріңіз, топтар, MFA және пайдаланушы карточкасы сілтемесі.",
    ),
    body: [
      t(
        "Первый вход может требовать смены пароля и включения MFA (/setup). Выход для SAML идёт через SLO.",
        "First sign-in may require password change and MFA (/setup). SAML sign-out uses SLO.",
        "Алғашқы кіру құпия сөз ауыстыру мен MFA талап етуі мүмкін (/setup). SAML шығу — SLO.",
      ),
    ],
    related: ["users", "config"],
  },
  {
    id: "workflows",
    group: "start",
    title: t("Сквозные сценарии", "End-to-end workflows", "Сквозной сценарийлер"),
    summary: t(
      "Как связать модули: доступ, секреты, политики, расследование.",
      "How modules connect: access, secrets, policies, investigation.",
      "Модульдер қалай байланысады: қолжетімділік, құпиялар, саясат, тергеу.",
    ),
    body: [
      t(
        "1) Доступ: Активы → ACL + Access Policy (JEA) → при необходимости JIT/Запросы → Подключить → (four-eyes) → Сессия → при необходимости Watch/Replay.",
        "1) Access: Assets → ACL + Access Policy (JEA) → optional JIT/Requests → Connect → (four-eyes) → Session → optional Watch/Replay.",
        "1) Қолжетімділік: Активтер → ACL + Policy → JIT/Сұраулар → Қосу → (four-eyes) → Сеанс → Watch/Replay.",
      ),
      t(
        "2) Секреты: учётка → Checkout (+ dual-control в Запросах) → Reveal → check-in; или Password sync → Rotate all; или Rotate на карточке.",
        "2) Secrets: account → Checkout (+ dual-control in Requests) → Reveal → check-in; or Password sync → Rotate all; or Rotate on the card.",
        "2) Құпиялар: тіркелгі → Checkout → Reveal → check-in; немесе Password sync → Rotate all.",
      ),
      t(
        "3) Политики: JEA packs + Policy → ACL/Tag ACL → эффект на SSH/SQL/HTTP/RDP; проверка Attack sim; контроль в Аудите/Аналитике.",
        "3) Policies: JEA packs + Policy → ACL/Tag ACL → effect on SSH/SQL/HTTP/RDP; verify with Attack sim; monitor in Audit/Analytics.",
        "3) Саясат: JEA + Policy → ACL → SSH/SQL/HTTP/RDP; Attack sim; Аудит/Талдау.",
      ),
      t(
        "4) Расследование: Сессии/Расследование → Replay/OCR/файлы → Аудит → Compliance-отчёт.",
        "4) Investigation: Sessions/Forensic → Replay/OCR/files → Audit → Compliance report.",
        "4) Тергеу: Сеанстар/Тергеу → Replay/OCR → Аудит → Compliance есебі.",
      ),
      t(
        "5) Люди: Пользователи → одна роль (operator / auditor / owner / security; admin только ИБ-админам PAM) → для operator выдать ACL или дождаться JIT; для owner указать его в карточке актива.",
        "5) People: Users → one role (operator / auditor / owner / security; admin only for PAM admins) → for operator grant ACL or wait for JIT; for owner set them on the asset card.",
        "5) Адамдар: Пайдаланушылар → бір рөл → operator-ге ACL немесе JIT; owner-ді актив карточкасында көрсету.",
      ),
    ],
    related: ["assets", "requests", "jea", "sessions", "forensic", "desktop", "users"],
  },
];

export function helpText(lang: Lang, value: LText): string {
  return value[lang] || value.en || value.ru;
}

export function findTopic(id: string): HelpTopic | undefined {
  return HELP_TOPICS.find((t) => t.id === id);
}
