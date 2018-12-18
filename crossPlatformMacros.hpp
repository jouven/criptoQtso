//because windows sucks...

#ifndef CRYPTOQTSO_CROSSPLATFORMMACROS_HPP
#define CRYPTOQTSO_CROSSPLATFORMMACROS_HPP

#include <QtCore/QtGlobal>

//remember to define this variable in the .pro file
#if defined(CRYPTOQTSO_LIBRARY)
#  define EXPIMP_CRYPTOQTSO Q_DECL_EXPORT
#else
#  define EXPIMP_CRYPTOQTSO Q_DECL_IMPORT
#endif

#endif // CRYPTOQTSO_CROSSPLATFORMMACROS_HPP
