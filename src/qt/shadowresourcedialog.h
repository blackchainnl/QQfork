// Copyright (c) 2026 The Blackcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_SHADOWRESOURCEDIALOG_H
#define BITCOIN_QT_SHADOWRESOURCEDIALOG_H

#include <node/shadow_resource_monitor.h>

#include <QDialog>
#include <QThread>

#include <atomic>
#include <memory>
#include <optional>
#include <string>

class QLabel;
class QPlainTextEdit;
class QPushButton;
class QShowEvent;
class QHideEvent;
class QTimer;

namespace interfaces {
class Node;
}

/**
 * Small injectable boundary around the node operations used by the resource
 * monitor. Production uses interfaces::Node; Qt tests use a deterministic
 * fake without constructing or mutating a chainstate.
 */
class ShadowResourceBackend
{
public:
    virtual ~ShadowResourceBackend() = default;
    virtual node::ShadowResourceStatus resourceStatus() = 0;
    virtual node::ShadowSupplyScanProgress scanProgress() = 0;
    virtual bool requestAbort() = 0;
    virtual std::string runSupplyScan(bool allow_unqualified_resource_scan) = 0;
};

/**
 * Native, wallet-independent operator surface for the scoped Quantum Quasar
 * resource envelope and the optional full circulating-supply scan.
 */
class ShadowResourceDialog : public QDialog
{
public:
    explicit ShadowResourceDialog(interfaces::Node& node, QWidget* parent = nullptr);
    explicit ShadowResourceDialog(std::shared_ptr<ShadowResourceBackend> backend,
                                  QWidget* parent = nullptr);
    ~ShadowResourceDialog() override;

    /** Prevent new work and request cooperative cancellation without waiting. */
    void requestShutdown();
    /** Stop and join the worker. Safe to call more than once. */
    void join();

protected:
    void showEvent(QShowEvent* event) override;
    void hideEvent(QHideEvent* event) override;

private:
    void buildUi();
    void requestStatusRefresh();
    void pollProgress();
    void applyStatus(const node::ShadowResourceStatus& status,
                     const node::ShadowSupplyScanProgress& progress);
    void applyProgress(const node::ShadowSupplyScanProgress& progress);
    void updateButtons(const node::ShadowSupplyScanProgress& progress);
    void startSupplyScan();
    bool confirmUnqualifiedOneCallScan() const;
    void requestAbort();
    void showStatusError(const QString& error);
    void showScanResult(const QString& result, const QString& error);

    std::shared_ptr<ShadowResourceBackend> m_backend;
    std::shared_ptr<std::atomic<bool>> m_shutdown_requested;
    QThread m_worker_thread;
    QObject* m_worker{nullptr};
    QTimer* m_poll_timer{nullptr};
    QTimer* m_status_timer{nullptr};

    QLabel* m_status_summary{nullptr};
    QLabel* m_warning{nullptr};
    QLabel* m_operator_action{nullptr};
    QPlainTextEdit* m_status_details{nullptr};
    QLabel* m_scan_summary{nullptr};
    QPlainTextEdit* m_scan_details{nullptr};
    QPlainTextEdit* m_scan_result{nullptr};
    QPushButton* m_refresh_button{nullptr};
    QPushButton* m_scan_button{nullptr};
    QPushButton* m_abort_button{nullptr};

    std::optional<node::ShadowResourceStatus> m_last_status;
    node::ShadowSupplyScanProgress m_last_progress;
    bool m_refresh_in_flight{false};
    bool m_scan_in_flight{false};
    bool m_stopping{false};
    bool m_joined{false};
};

#endif // BITCOIN_QT_SHADOWRESOURCEDIALOG_H
