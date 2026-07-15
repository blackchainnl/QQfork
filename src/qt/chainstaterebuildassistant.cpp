// Copyright (c) 2026 The Blackcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/chainstaterebuildassistant.h>

#include <clientversion.h>

#include <QMessageBox>
#include <QPushButton>
#include <QRegularExpression>

namespace ChainstateRebuildAssistant {
namespace {

QString NormalizedOption(QString argument)
{
    if (argument.startsWith('/')) argument[0] = '-';
    while (argument.startsWith("--")) argument.remove(0, 1);
    return argument.toLower();
}

bool IsOption(const QString& argument, const QString& name)
{
    const QString normalized = NormalizedOption(argument);
    const QString negated = "-no" + name.mid(1);
    return normalized == name || normalized.startsWith(name + '=') ||
        normalized == negated || normalized.startsWith(negated + '=');
}

QString QuoteUnix(const QString& argument)
{
    if (!argument.isEmpty() &&
        !argument.contains(QRegularExpression{
            QStringLiteral("[^A-Za-z0-9_@%+=:,./-]")})) {
        return argument;
    }
    QString quoted = argument;
    quoted.replace(QStringLiteral("'"), QStringLiteral("'\\''"));
    return QStringLiteral("'") + quoted + QStringLiteral("'");
}

QString QuoteWindows(const QString& argument)
{
    if (!argument.isEmpty() &&
        !argument.contains(QRegularExpression{QStringLiteral("[\\s\"]")})) {
        return argument;
    }
    QString result{'"'};
    int backslashes{0};
    for (const QChar character : argument) {
        if (character == '\\') {
            ++backslashes;
            continue;
        }
        if (character == '"') {
            result += QString(backslashes * 2 + 1, '\\');
            result += character;
        } else {
            result += QString(backslashes, '\\');
            result += character;
        }
        backslashes = 0;
    }
    result += QString(backslashes * 2, '\\');
    result += '"';
    return result;
}

QStringList SanitizedArguments(const QStringList& arguments)
{
    QStringList result;
    for (const QString& argument : arguments) {
        if (IsOption(argument, "-gui-chainstate-rebuild") ||
            IsOption(argument, "-reindex-chainstate") ||
            IsOption(argument, "-reindex")) {
            continue;
        }
        result.push_back(argument);
    }
    return result;
}

} // namespace

Action ResolveAction(Condition condition, Choice choice)
{
    if (condition == Condition::ALREADY_COMPLETE) return Action::CONTINUE_STARTUP;
    if (condition == Condition::FULL_REINDEX_REQUIRED) {
        return Action::SHOW_FULL_REINDEX_INSTRUCTIONS;
    }
    return choice == Choice::AUTOMATIC
        ? Action::RELAUNCH_CHAINSTATE_REBUILD
        : Action::SHOW_CHAINSTATE_INSTRUCTIONS;
}

Phase ParsePhase(const QString& value)
{
    if (value == QLatin1String("rebuild")) return Phase::REBUILD;
    if (value == QLatin1String("verify")) return Phase::VERIFY;
    return Phase::NONE;
}

QString PhaseName(Phase phase)
{
    if (phase == Phase::REBUILD) return QStringLiteral("rebuild");
    if (phase == Phase::VERIFY) return QStringLiteral("verify");
    return {};
}

QStringList BuildRelaunchArguments(const QStringList& arguments, Phase phase)
{
    QStringList result = SanitizedArguments(arguments);
    if (phase == Phase::REBUILD) result.push_back(QStringLiteral("-reindex-chainstate"));
    if (phase != Phase::NONE) {
        result.push_back(QStringLiteral("-gui-chainstate-rebuild=") + PhaseName(phase));
    }
    return result;
}

QStringList BuildManualRebuildArguments(const QStringList& arguments)
{
    QStringList result = SanitizedArguments(arguments);
    result.push_back(QStringLiteral("-reindex-chainstate"));
    return result;
}

QStringList BuildFullReindexArguments(const QStringList& arguments)
{
    QStringList result = SanitizedArguments(arguments);
    for (auto it = result.begin(); it != result.end();) {
        if (IsOption(*it, "-reindex") || IsOption(*it, "-prune")) {
            it = result.erase(it);
        } else {
            ++it;
        }
    }
    result.push_back(QStringLiteral("-prune=0"));
    result.push_back(QStringLiteral("-reindex"));
    return result;
}

QString FormatCommand(const QString& executable, const QStringList& arguments,
                      CommandPlatform platform)
{
    const auto quote = platform == CommandPlatform::WINDOWS ? QuoteWindows : QuoteUnix;
    QStringList command{quote(executable)};
    for (const QString& argument : arguments) command.push_back(quote(argument));
    return command.join(' ');
}

CommandPlatform CurrentCommandPlatform()
{
#ifdef Q_OS_WIN
    return CommandPlatform::WINDOWS;
#else
    return CommandPlatform::UNIX;
#endif
}

Choice PromptForRebuild(QWidget* parent)
{
    QMessageBox box{QMessageBox::Warning, PACKAGE_NAME,
                    QObject::tr("A one-time chainstate rebuild is required"),
                    QMessageBox::NoButton, parent};
    box.setWindowModality(Qt::ApplicationModal);
    box.setText(QObject::tr(
        "This existing data directory was created before the authenticated "
        "v30.1.1 shadow-state upgrade. Blackcoin cannot safely load wallets, "
        "stake, mine, or continue until the chainstate is rebuilt."));
    box.setInformativeText(QObject::tr(
        "Wallet files and available block files are preserved. Automatic mode "
        "restarts Blackcoin once to rebuild, then once normally to verify the "
        "replacement before wallet automation is allowed. The temporary source "
        "chainstate backup is retired only after that separate verification "
        "succeeds; a failure or interruption preserves it for recovery."));
    QPushButton* automatic = box.addButton(QObject::tr("Rebuild automatically"), QMessageBox::AcceptRole);
    QPushButton* manual = box.addButton(QObject::tr("Exit and rebuild manually"), QMessageBox::RejectRole);
    // Pressing Enter must not authorize a rebuild. Automatic mode requires an
    // affirmative click; Enter, Esc, and window close all take the safe exit.
    box.setDefaultButton(manual);
    box.setEscapeButton(manual);
    box.exec();
    return box.clickedButton() == automatic ? Choice::AUTOMATIC :
        box.clickedButton() == manual ? Choice::MANUAL : Choice::CLOSED;
}

void ShowManualRebuildInstructions(QWidget* parent, const QString& executable,
                                   const QStringList& original_arguments)
{
    const QString command = FormatCommand(
        executable, BuildManualRebuildArguments(original_arguments),
        CurrentCommandPlatform());
    QMessageBox box{QMessageBox::Information, PACKAGE_NAME,
                    QObject::tr("Blackcoin will exit without changing chainstate."),
                    QMessageBox::Ok, parent};
    box.setInformativeText(QObject::tr(
        "After confirming your wallet backup, run this one-time command. The "
        "process exits automatically at the protected commit point; then reopen "
        "Blackcoin normally without either reindex option to verify the rebuilt "
        "state. The temporary source chainstate backup is retired only after "
        "successful verification; a failure or interruption preserves it. Do "
        "not add reindex-chainstate to the configuration file."));
    box.setDetailedText(command);
    box.exec();
}

void ShowFullReindexInstructions(QWidget* parent, const QString& executable,
                                 const QStringList& original_arguments)
{
    const QString command = FormatCommand(
        executable, BuildFullReindexArguments(original_arguments),
        CurrentCommandPlatform());
    QMessageBox box{QMessageBox::Critical, PACKAGE_NAME,
                    QObject::tr("Complete local block history is required"),
                    QMessageBox::Ok, parent};
    box.setWindowModality(Qt::ApplicationModal);
    box.setText(QObject::tr(
        "The protected chainstate-only rebuild stopped before moving or wiping "
        "the existing chainstate because local block history is incomplete."));
    box.setInformativeText(QObject::tr(
        "Wallets and available blocks were preserved. Exit, keep your wallet "
        "backup, disable pruning, and use the full recovery command below to "
        "redownload and validate missing history."));
    box.setDetailedText(command);
    box.exec();
}

} // namespace ChainstateRebuildAssistant
