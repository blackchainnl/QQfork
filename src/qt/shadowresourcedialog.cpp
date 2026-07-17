// Copyright (c) 2026 The Blackcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/shadowresourcedialog.h>

#include <interfaces/node.h>
#include <univalue.h>

#include <QDialogButtonBox>
#include <QGroupBox>
#include <QHideEvent>
#include <QLabel>
#include <QMessageBox>
#include <QMetaObject>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QShowEvent>
#include <QTimer>
#include <QVBoxLayout>

#include <cassert>
#include <exception>
#include <utility>

namespace {

class NodeShadowResourceBackend final : public ShadowResourceBackend
{
public:
    explicit NodeShadowResourceBackend(interfaces::Node& node) : m_node(node) {}

    node::ShadowResourceStatus resourceStatus() override
    {
        return m_node.getShadowResourceStatus();
    }

    node::ShadowSupplyScanProgress scanProgress() override
    {
        return m_node.getShadowSupplyScanProgress();
    }

    bool requestAbort() override
    {
        return m_node.abortCirculatingSupplyScan();
    }

    std::string runSupplyScan(bool allow_unqualified_resource_scan) override
    {
        return m_node.runCirculatingSupplyScan(
            allow_unqualified_resource_scan).write(2);
    }

private:
    interfaces::Node& m_node;
};

QString YesNo(bool value)
{
    return value ? QObject::tr("yes") : QObject::tr("no");
}

QString OptionalNumber(int value)
{
    return value >= 0 ? QString::number(value) : QObject::tr("unavailable");
}

QString OptionalText(const std::string& value)
{
    return value.empty() ? QObject::tr("unavailable")
                         : QString::fromStdString(value);
}

QString Bytes(uint64_t value)
{
    constexpr double GIB = 1024.0 * 1024.0 * 1024.0;
    return QObject::tr("%1 bytes (%2 GiB)")
        .arg(QString::number(value), QString::number(value / GIB, 'f', 2));
}

QString RpcErrorText(const UniValue& error)
{
    if (error.isObject()) {
        const UniValue& message = error["message"];
        if (message.isStr()) return QString::fromStdString(message.get_str());
    }
    return QString::fromStdString(error.write());
}

QString StatusDetails(const node::ShadowResourceStatus& status)
{
    QStringList lines;
    auto add = [&](const QString& name, const QString& value) {
        lines.push_back(name + QStringLiteral(": ") + value);
    };

    add(QObject::tr("Scope"),
        QObject::tr("scoped mainnet operating envelope; not a consensus bound"));
    add(QObject::tr("Schema"),
        QStringLiteral("blackcoin.shadow.resource_operational.v1"));
    add(QObject::tr("Model class"), QStringLiteral("scoped_operational"));
    add(QObject::tr("Universal consensus bound"), QObject::tr("no"));
    add(QObject::tr("Production evidence authorization"),
        QStringLiteral("external_exact_sha_report_required"));
    add(QObject::tr("Applicable"), YesNo(status.applicable));
    add(QObject::tr("Measurements available"), YesNo(status.measurements_available));
    add(QObject::tr("Status"),
        QString::fromLatin1(node::ShadowResourceStatusName(status.level)));
    add(QObject::tr("Measured height"), OptionalNumber(status.height));
    add(QObject::tr("Measured best block"), OptionalText(status.best_block));
    add(QObject::tr("Estimated chainstate"), Bytes(status.estimated_chainstate_bytes));
    add(QObject::tr("Filesystem available"), Bytes(status.filesystem_available_bytes));
    add(QObject::tr("Modeled shadow logical bytes"),
        Bytes(node::SHADOW_RESOURCE_MODELED_SHADOW_LOGICAL_BYTES));
    add(QObject::tr("Policy disk amplification factor"),
        QString::number(node::SHADOW_RESOURCE_POLICY_DISK_AMPLIFICATION_FACTOR));
    add(QObject::tr("Modeled shadow physical reserve"),
        Bytes(node::SHADOW_RESOURCE_MODELED_SHADOW_PHYSICAL_RESERVE_BYTES));
    add(QObject::tr("Current chainstate estimate allowance"),
        Bytes(node::SHADOW_RESOURCE_CURRENT_CHAINSTATE_ESTIMATE_ALLOWANCE_BYTES));
    add(QObject::tr("Background physical reserve per block"),
        Bytes(node::SHADOW_RESOURCE_BACKGROUND_PHYSICAL_RESERVE_BYTES_PER_BLOCK));
    add(QObject::tr("Background growth records per block"),
        QString::number(node::SHADOW_RESOURCE_BACKGROUND_GROWTH_RECORDS_PER_BLOCK));
    add(QObject::tr("Maximum synthetic records"),
        QString::number(node::SHADOW_RESOURCE_MAX_SYNTHETIC_RECORDS));
    add(QObject::tr("Maximum modeled shadow logical bytes per block"),
        Bytes(node::SHADOW_RESOURCE_MAX_MODELED_SHADOW_LOGICAL_BYTES_PER_BLOCK));
    add(QObject::tr("Maximum modeled shadow physical bytes per block"),
        Bytes(node::SHADOW_RESOURCE_MAX_MODELED_SHADOW_PHYSICAL_BYTES_PER_BLOCK));
    add(QObject::tr("Maximum modeled shadow records per block"),
        QString::number(node::SHADOW_RESOURCE_MAX_MODELED_SHADOW_RECORDS_PER_BLOCK));
    add(QObject::tr("Modeled legacy shadow records per block"),
        QString::number(node::SHADOW_RESOURCE_MODELED_LEGACY_SHADOW_RECORDS_PER_BLOCK));
    add(QObject::tr("Modeled legacy shadow logical bytes per block"),
        Bytes(node::SHADOW_RESOURCE_MODELED_LEGACY_SHADOW_LOGICAL_BYTES_PER_BLOCK));
    add(QObject::tr("Remaining Gold Rush blocks"),
        QString::number(status.remaining_gold_rush_blocks));
    add(QObject::tr("Projected remaining shadow physical bytes"),
        Bytes(status.projected_remaining_shadow_physical_bytes));
    add(QObject::tr("Projected background growth bytes"),
        Bytes(status.projected_background_growth_bytes));
    add(QObject::tr("Minimum free bytes"), Bytes(status.minimum_free_bytes));
    add(QObject::tr("Required free bytes"), Bytes(status.required_free_bytes));
    add(QObject::tr("Warning free bytes"), Bytes(status.warning_free_bytes));
    add(QObject::tr("Immediate scan free bytes"), Bytes(status.immediate_scan_free_bytes));
    add(QObject::tr("Critical free bytes"), Bytes(status.critical_free_bytes));
    add(QObject::tr("Maximum estimated chainstate bytes"),
        Bytes(status.maximum_estimated_chainstate_bytes));
    add(QObject::tr("Maximum records per cursor"),
        QString::number(status.maximum_records_per_cursor));
    add(QObject::tr("Maximum sequential visits"),
        QString::number(status.maximum_sequential_visits));
    add(QObject::tr("Maximum point seeks"),
        QString::number(status.maximum_point_seeks));
    add(QObject::tr("Absolute records per cursor"),
        QString::number(status.absolute_records_per_cursor));
    add(QObject::tr("Absolute point seeks"),
        QString::number(status.absolute_point_seeks));
    add(QObject::tr("Support through height"),
        QString::number(status.support_through_height));
    add(QObject::tr("Within supported height"), YesNo(status.within_supported_height));
    add(QObject::tr("Within chainstate size"), YesNo(status.within_chainstate_size));
    add(QObject::tr("Within immediate scan free space"),
        YesNo(status.within_immediate_scan_free_space));
    add(QObject::tr("Within projected free space"),
        YesNo(status.within_projected_free_space));
    add(QObject::tr("Critical free space satisfied"),
        YesNo(status.critical_free_space_satisfied));
    add(QObject::tr("Operational envelope satisfied"),
        YesNo(status.operational_envelope_satisfied));
    add(QObject::tr("Diagnostic scan authorized without override"),
        YesNo(status.diagnostic_scan_default_authorized));
    add(QObject::tr("Consensus behavior changed"), QObject::tr("no"));
    add(QObject::tr("Automatic shutdown"), QObject::tr("no"));
    add(QObject::tr("Automatic network disable"), QObject::tr("no"));
    return lines.join('\n');
}

QString ProgressDetails(const node::ShadowSupplyScanProgress& progress)
{
    QStringList lines;
    auto add = [&](const QString& name, const QString& value) {
        lines.push_back(name + QStringLiteral(": ") + value);
    };
    add(QObject::tr("Active"), YesNo(progress.active));
    add(QObject::tr("Scan ID"), QString::number(progress.scan_id));
    add(QObject::tr("Snapshot height"), OptionalNumber(progress.height));
    add(QObject::tr("Snapshot best block"), OptionalText(progress.best_block));
    add(QObject::tr("Stage"), QString::fromStdString(progress.stage));
    add(QObject::tr("Abort requested"), YesNo(progress.abort_requested));
    add(QObject::tr("Marker records scanned"),
        QString::number(progress.marker_records_scanned));
    add(QObject::tr("UTXO records scanned"),
        QString::number(progress.utxo_records_scanned));
    add(QObject::tr("Active Coin batch payload bytes scanned"),
        QString::number(progress.active_coin_batch_payload_bytes_scanned));
    add(QObject::tr("Authenticated shadow records scanned"),
        QString::number(progress.authenticated_shadow_records_scanned));
    add(QObject::tr("Authenticated shadow batch payload bytes scanned"),
        QString::number(progress.authenticated_shadow_batch_payload_bytes_scanned));
    add(QObject::tr("Provenance point seeks"),
        QString::number(progress.provenance_point_seeks));
    add(QObject::tr("Demurrage point seeks"),
        QString::number(progress.demurrage_point_seeks));
    add(QObject::tr("Elapsed milliseconds"),
        QString::number(progress.elapsed_milliseconds));
    add(QObject::tr("Started at (Unix)"),
        QString::number(progress.started_at_unix));
    add(QObject::tr("Completed at (Unix)"),
        QString::number(progress.completed_at_unix));
    add(QObject::tr("Last outcome"), QString::fromStdString(progress.last_outcome));
    add(QObject::tr("Last reason"), OptionalText(progress.last_reason));
    return lines.join('\n');
}

} // namespace

ShadowResourceDialog::ShadowResourceDialog(interfaces::Node& node,
                                           QWidget* parent)
    : ShadowResourceDialog(
          std::make_shared<NodeShadowResourceBackend>(node), parent)
{
}

ShadowResourceDialog::ShadowResourceDialog(
    std::shared_ptr<ShadowResourceBackend> backend, QWidget* parent)
    : QDialog(parent),
      m_backend(std::move(backend)),
      m_shutdown_requested(std::make_shared<std::atomic<bool>>(false)),
      m_worker(new QObject)
{
    assert(m_backend);
    setAttribute(Qt::WA_DeleteOnClose, false);
    setWindowTitle(tr("Quantum Quasar resource monitor"));
    setMinimumSize(760, 680);
    buildUi();

    m_worker->moveToThread(&m_worker_thread);
    connect(&m_worker_thread, &QThread::finished,
            m_worker, &QObject::deleteLater);
    m_worker_thread.start();

    m_poll_timer = new QTimer(this);
    m_poll_timer->setInterval(500);
    connect(m_poll_timer, &QTimer::timeout,
            this, [this] { pollProgress(); });

    // Progress is cheap process-wide monitor state and is useful at high
    // frequency. Disk/chainstate status is refreshed separately so that the
    // displayed height and resource envelope cannot remain stale indefinitely.
    m_status_timer = new QTimer(this);
    m_status_timer->setObjectName(
        QStringLiteral("shadowResourceStatusRefreshTimer"));
    m_status_timer->setInterval(30000);
    connect(m_status_timer, &QTimer::timeout,
            this, [this] { requestStatusRefresh(); });
}

ShadowResourceDialog::~ShadowResourceDialog()
{
    join();
}

void ShadowResourceDialog::requestShutdown()
{
    if (m_stopping) return;
    m_stopping = true;
    m_shutdown_requested->store(true, std::memory_order_release);
    if (m_poll_timer) m_poll_timer->stop();
    if (m_status_timer) m_status_timer->stop();
    updateButtons(m_last_progress);
    try {
        if (m_scan_in_flight || m_backend->scanProgress().active) {
            m_backend->requestAbort();
        }
    } catch (...) {
        // Shutdown still owns the final RPC interrupt. Destruction must not
        // turn a diagnostic status failure into a process failure.
    }
}

void ShadowResourceDialog::join()
{
    requestShutdown();
    if (m_joined) return;
    m_worker_thread.quit();
    // A scan can cross from the queued worker call into TryBegin immediately
    // after the first cancellation probe. Re-probe while joining so that this
    // start/teardown race cannot strand the GUI shutdown behind a live scan.
    while (!m_worker_thread.wait(50)) {
        try {
            if (m_backend->scanProgress().active) {
                m_backend->requestAbort();
            }
        } catch (...) {
            // Keep joining; node shutdown owns the final RPC interruption.
        }
    }
    m_worker = nullptr;
    m_joined = true;
}

void ShadowResourceDialog::buildUi()
{
    auto* root = new QVBoxLayout(this);

    auto* scope = new QLabel(tr(
        "This page reports a scoped v30.1.1 operating envelope. It is not a "
        "consensus limit. It never disables validation, networking, staking, "
        "mining, or the daemon. A full supply scan is optional and returns no "
        "partial monetary result if it fails or is cancelled."), this);
    scope->setObjectName(QStringLiteral("shadowResourceScope"));
    scope->setWordWrap(true);
    root->addWidget(scope);

    auto* status_group = new QGroupBox(tr("Current operating status"), this);
    auto* status_layout = new QVBoxLayout(status_group);
    m_status_summary = new QLabel(tr("Waiting for a fresh measurement…"), status_group);
    m_status_summary->setObjectName(QStringLiteral("shadowResourceStatusSummary"));
    m_status_summary->setWordWrap(true);
    status_layout->addWidget(m_status_summary);
    m_warning = new QLabel(status_group);
    m_warning->setObjectName(QStringLiteral("shadowResourceWarning"));
    m_warning->setWordWrap(true);
    status_layout->addWidget(m_warning);
    m_operator_action = new QLabel(status_group);
    m_operator_action->setObjectName(QStringLiteral("shadowResourceOperatorAction"));
    m_operator_action->setWordWrap(true);
    status_layout->addWidget(m_operator_action);
    m_status_details = new QPlainTextEdit(status_group);
    m_status_details->setObjectName(QStringLiteral("shadowResourceStatusDetails"));
    m_status_details->setReadOnly(true);
    m_status_details->setMinimumHeight(170);
    status_layout->addWidget(m_status_details);
    root->addWidget(status_group, 1);

    auto* scan_group = new QGroupBox(tr("Optional circulating-supply scan"), this);
    auto* scan_layout = new QVBoxLayout(scan_group);
    m_scan_summary = new QLabel(tr("No scan has run in this process."), scan_group);
    m_scan_summary->setObjectName(QStringLiteral("shadowSupplyScanSummary"));
    m_scan_summary->setWordWrap(true);
    scan_layout->addWidget(m_scan_summary);
    m_scan_details = new QPlainTextEdit(scan_group);
    m_scan_details->setObjectName(QStringLiteral("shadowSupplyScanDetails"));
    m_scan_details->setReadOnly(true);
    m_scan_details->setMinimumHeight(130);
    scan_layout->addWidget(m_scan_details);
    m_scan_result = new QPlainTextEdit(scan_group);
    m_scan_result->setObjectName(QStringLiteral("shadowSupplyScanResult"));
    m_scan_result->setReadOnly(true);
    m_scan_result->setPlaceholderText(tr(
        "A completed scan result or a failure reason will appear here."));
    m_scan_result->setMinimumHeight(110);
    scan_layout->addWidget(m_scan_result);

    auto* controls = new QDialogButtonBox(scan_group);
    m_refresh_button = controls->addButton(tr("Refresh status"),
                                           QDialogButtonBox::ActionRole);
    m_refresh_button->setObjectName(QStringLiteral("shadowResourceRefreshButton"));
    m_scan_button = controls->addButton(tr("Run full supply scan"),
                                        QDialogButtonBox::ActionRole);
    m_scan_button->setObjectName(QStringLiteral("shadowSupplyScanButton"));
    m_abort_button = controls->addButton(tr("Cancel active scan"),
                                         QDialogButtonBox::ActionRole);
    m_abort_button->setObjectName(QStringLiteral("shadowSupplyAbortButton"));
    auto* close_button = controls->addButton(QDialogButtonBox::Close);
    close_button->setObjectName(QStringLiteral("shadowResourceCloseButton"));
    scan_layout->addWidget(controls);
    root->addWidget(scan_group, 1);

    connect(m_refresh_button, &QPushButton::clicked,
            this, [this] { requestStatusRefresh(); });
    connect(m_scan_button, &QPushButton::clicked,
            this, [this] { startSupplyScan(); });
    connect(m_abort_button, &QPushButton::clicked,
            this, [this] { requestAbort(); });
    connect(controls, &QDialogButtonBox::rejected, this, &QDialog::hide);

    m_refresh_button->setEnabled(true);
    m_scan_button->setEnabled(false);
    m_abort_button->setEnabled(false);
}

void ShadowResourceDialog::showEvent(QShowEvent* event)
{
    QDialog::showEvent(event);
    if (!m_stopping) {
        pollProgress();
        requestStatusRefresh();
        m_poll_timer->start();
        m_status_timer->start();
    }
}

void ShadowResourceDialog::hideEvent(QHideEvent* event)
{
    if (m_poll_timer) m_poll_timer->stop();
    if (m_status_timer) m_status_timer->stop();
    QDialog::hideEvent(event);
}

void ShadowResourceDialog::requestStatusRefresh()
{
    if (m_stopping || m_refresh_in_flight) return;
    m_refresh_in_flight = true;
    updateButtons(m_last_progress);
    const auto backend = m_backend;
    const auto shutdown_requested = m_shutdown_requested;
    QPointer<ShadowResourceDialog> guard{this};
    const bool queued = QMetaObject::invokeMethod(
        m_worker, [backend, shutdown_requested, guard] {
            try {
                if (shutdown_requested->load(std::memory_order_acquire)) return;
                const node::ShadowResourceStatus status = backend->resourceStatus();
                if (shutdown_requested->load(std::memory_order_acquire)) return;
                const node::ShadowSupplyScanProgress progress = backend->scanProgress();
                if (shutdown_requested->load(std::memory_order_acquire)) return;
                if (!guard) return;
                QMetaObject::invokeMethod(guard, [guard, status, progress] {
                    if (!guard || guard->m_stopping) return;
                    guard->m_refresh_in_flight = false;
                    guard->applyStatus(status, progress);
                }, Qt::QueuedConnection);
            } catch (const std::exception& error) {
                if (shutdown_requested->load(std::memory_order_acquire)) return;
                if (!guard) return;
                const QString message = QString::fromLocal8Bit(error.what());
                QMetaObject::invokeMethod(guard, [guard, message] {
                    if (!guard || guard->m_stopping) return;
                    guard->m_refresh_in_flight = false;
                    guard->showStatusError(message);
                }, Qt::QueuedConnection);
            } catch (...) {
                if (shutdown_requested->load(std::memory_order_acquire)) return;
                if (!guard) return;
                QMetaObject::invokeMethod(guard, [guard] {
                    if (!guard || guard->m_stopping) return;
                    guard->m_refresh_in_flight = false;
                    guard->showStatusError(
                        tr("The node returned an unknown status error."));
                }, Qt::QueuedConnection);
            }
        }, Qt::QueuedConnection);
    if (!queued) {
        m_refresh_in_flight = false;
        showStatusError(tr("The resource-status worker is unavailable."));
    }
}

void ShadowResourceDialog::pollProgress()
{
    if (m_stopping) return;
    try {
        applyProgress(m_backend->scanProgress());
    } catch (const std::exception& error) {
        showStatusError(QString::fromLocal8Bit(error.what()));
    }
}

void ShadowResourceDialog::applyStatus(
    const node::ShadowResourceStatus& status,
    const node::ShadowSupplyScanProgress& progress)
{
    m_last_status = status;
    m_status_summary->setText(tr("Status: %1 — measured height: %2")
        .arg(QString::fromLatin1(node::ShadowResourceStatusName(status.level)),
             OptionalNumber(status.height)));
    m_warning->setText(status.warning.empty()
        ? tr("Warning: none")
        : tr("Warning: %1").arg(QString::fromStdString(status.warning)));
    m_operator_action->setText(tr("Operator action: %1")
        .arg(QString::fromStdString(status.operator_action)));
    m_status_details->setPlainText(StatusDetails(status));
    applyProgress(progress);
}

void ShadowResourceDialog::applyProgress(
    const node::ShadowSupplyScanProgress& progress)
{
    m_last_progress = progress;
    if (progress.active) {
        m_scan_summary->setText(tr("Scan %1 is active at stage %2. %3 records visited.")
            .arg(QString::number(progress.scan_id),
                 QString::fromStdString(progress.stage),
                 QString::number(progress.marker_records_scanned +
                                 progress.utxo_records_scanned)));
    } else {
        m_scan_summary->setText(tr("Last outcome: %1. %2")
            .arg(QString::fromStdString(progress.last_outcome),
                 QString::fromStdString(progress.last_reason)));
    }
    m_scan_details->setPlainText(ProgressDetails(progress));
    updateButtons(progress);
}

void ShadowResourceDialog::updateButtons(
    const node::ShadowSupplyScanProgress& progress)
{
    const bool active = progress.active || m_scan_in_flight;
    bool hard_scan_preconditions = false;
    if (m_last_status) {
        const node::ShadowResourceStatus& status = *m_last_status;
        hard_scan_preconditions = !status.applicable ||
            (status.measurements_available &&
             status.within_immediate_scan_free_space &&
             status.critical_free_space_satisfied);
    }
    m_refresh_button->setEnabled(!m_refresh_in_flight && !m_stopping);
    m_scan_button->setEnabled(!active && hard_scan_preconditions &&
                              !m_stopping);
    m_abort_button->setEnabled(progress.active && !progress.abort_requested &&
                               !m_stopping);
}

bool ShadowResourceDialog::confirmUnqualifiedOneCallScan() const
{
    QMessageBox box{QMessageBox::Warning,
                    tr("Authorize one scan outside the diagnostic envelope?"),
                    tr("This snapshot is outside the reviewed diagnostic "
                       "height or chainstate-size envelope. No scan has started."),
                    QMessageBox::NoButton,
                    const_cast<ShadowResourceDialog*>(this)};
    box.setObjectName(QStringLiteral("shadowResourceConsentDialog"));
    box.setInformativeText(tr(
        "Authorizing continues this one diagnostic call only. Consent is not "
        "saved, does not suppress warnings, and cannot bypass the 64 GiB "
        "pre-flush reserve, the critical integrity reserve, snapshot checks, "
        "shutdown, cancellation, overflow checks, or absolute work limits."));
    QPushButton* authorize = box.addButton(tr("Authorize this scan once"),
                                           QMessageBox::AcceptRole);
    authorize->setObjectName(QStringLiteral("shadowResourceAuthorizeOnceButton"));
    QPushButton* cancel = box.addButton(QMessageBox::Cancel);
    cancel->setObjectName(QStringLiteral("shadowResourceConsentCancelButton"));
    box.setDefaultButton(cancel);
    box.setEscapeButton(cancel);
    box.exec();
    return box.clickedButton() == authorize;
}

void ShadowResourceDialog::startSupplyScan()
{
    if (m_stopping || !m_last_status || m_scan_in_flight ||
        m_last_progress.active) return;
    const node::ShadowResourceStatus status = *m_last_status;
    const bool hard_scan_preconditions = !status.applicable ||
        (status.measurements_available &&
         status.within_immediate_scan_free_space &&
         status.critical_free_space_satisfied);
    if (!hard_scan_preconditions) {
        showScanResult({}, tr(
            "The hard storage or measurement preconditions are not satisfied. "
            "Explicit consent cannot bypass this protection."));
        return;
    }

    bool allow_unqualified_resource_scan = false;
    if (status.applicable && !status.diagnostic_scan_default_authorized) {
        if (!confirmUnqualifiedOneCallScan()) return;
        if (m_stopping) return;
        allow_unqualified_resource_scan = true;
    }

    m_scan_in_flight = true;
    m_scan_result->setPlainText(tr(
        "Preparing an immutable snapshot. The GUI remains responsive; use "
        "Cancel active scan to request cooperative cancellation."));
    updateButtons(m_last_progress);

    const auto backend = m_backend;
    const auto shutdown_requested = m_shutdown_requested;
    QPointer<ShadowResourceDialog> guard{this};
    const bool queued = QMetaObject::invokeMethod(m_worker,
        [backend, shutdown_requested, guard, allow_unqualified_resource_scan] {
            QString result;
            QString error;
            if (shutdown_requested->load(std::memory_order_acquire)) return;
            try {
                result = QString::fromStdString(
                    backend->runSupplyScan(allow_unqualified_resource_scan));
            } catch (const UniValue& rpc_error) {
                error = RpcErrorText(rpc_error);
            } catch (const std::exception& exception) {
                error = QString::fromLocal8Bit(exception.what());
            } catch (...) {
                error = tr("The node returned an unknown supply-scan error.");
            }
            if (shutdown_requested->load(std::memory_order_acquire)) return;
            if (!guard) return;
            QMetaObject::invokeMethod(guard, [guard, result, error] {
                if (!guard || guard->m_stopping) return;
                guard->m_scan_in_flight = false;
                guard->showScanResult(result, error);
                guard->pollProgress();
                guard->requestStatusRefresh();
            }, Qt::QueuedConnection);
        }, Qt::QueuedConnection);
    if (!queued) {
        m_scan_in_flight = false;
        showScanResult({}, tr("The supply-scan worker is unavailable."));
    }
}

void ShadowResourceDialog::requestAbort()
{
    if (!m_last_progress.active || m_last_progress.abort_requested) return;
    bool requested{false};
    try {
        // This backend method only flips the process-wide cooperative-cancel
        // flag under its tiny monitor mutex. It cannot wait behind the scan
        // worker, so cancellation stays usable while that worker is occupied.
        requested = m_backend->requestAbort();
    } catch (const std::exception& error) {
        showScanResult({}, QString::fromLocal8Bit(error.what()));
        return;
    }
    if (!requested) {
        showScanResult({}, tr("No active scan accepted the cancellation request."));
    }
    pollProgress();
}

void ShadowResourceDialog::showStatusError(const QString& error)
{
    m_last_status.reset();
    m_status_summary->setText(tr("Resource status unavailable: %1").arg(error));
    m_warning->setText(tr(
        "No scan can start until a fresh status measurement succeeds."));
    m_operator_action->clear();
    m_status_details->clear();
    updateButtons(m_last_progress);
}

void ShadowResourceDialog::showScanResult(const QString& result,
                                          const QString& error)
{
    if (!error.isEmpty()) {
        m_scan_result->setPlainText(tr(
            "Scan did not return a monetary result. Reason: %1").arg(error));
    } else {
        m_scan_result->setPlainText(tr("Completed immutable-snapshot result:\n%1")
                                    .arg(result));
    }
    updateButtons(m_last_progress);
}
