// Copyright (c) 2026 The Blackcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_CHAINSTATEREBUILDASSISTANT_H
#define BITCOIN_QT_CHAINSTATEREBUILDASSISTANT_H

#include <QString>
#include <QStringList>

class QWidget;

namespace ChainstateRebuildAssistant {

enum class Phase {
    NONE,
    REBUILD,
    VERIFY,
};

enum class Condition {
    REBUILD_REQUIRED,
    FULL_REINDEX_REQUIRED,
    ALREADY_COMPLETE,
};

enum class Choice {
    AUTOMATIC,
    MANUAL,
    CLOSED,
};

enum class Action {
    RELAUNCH_CHAINSTATE_REBUILD,
    SHOW_CHAINSTATE_INSTRUCTIONS,
    SHOW_FULL_REINDEX_INSTRUCTIONS,
    CONTINUE_STARTUP,
};

enum class CommandPlatform {
    UNIX,
    WINDOWS,
};

Action ResolveAction(Condition condition, Choice choice);
Phase ParsePhase(const QString& value);
QString PhaseName(Phase phase);

QStringList BuildRelaunchArguments(const QStringList& arguments, Phase phase);
QStringList BuildManualRebuildArguments(const QStringList& arguments);
QStringList BuildFullReindexArguments(const QStringList& arguments);
QString FormatCommand(const QString& executable, const QStringList& arguments,
                      CommandPlatform platform);
CommandPlatform CurrentCommandPlatform();

Choice PromptForRebuild(QWidget* parent);
void ShowManualRebuildInstructions(QWidget* parent, const QString& executable,
                                   const QStringList& original_arguments);
void ShowFullReindexInstructions(QWidget* parent, const QString& executable,
                                 const QStringList& original_arguments);

} // namespace ChainstateRebuildAssistant

#endif // BITCOIN_QT_CHAINSTATEREBUILDASSISTANT_H
