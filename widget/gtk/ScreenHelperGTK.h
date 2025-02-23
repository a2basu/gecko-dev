/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_widget_gtk_ScreenHelperGTK_h
#define mozilla_widget_gtk_ScreenHelperGTK_h

#include "mozilla/widget/ScreenManager.h"

#include "gdk/gdk.h"
#ifdef MOZ_X11
#  include <X11/Xlib.h>
#  include "X11UndefineNone.h"
#endif

namespace mozilla {
namespace widget {

class ScreenGetter {
 public:
  ScreenGetter() = default;
  virtual ~ScreenGetter(){};
};

class ScreenGetterGtk : public ScreenGetter {
 public:
  ScreenGetterGtk();
  ~ScreenGetterGtk();

#ifdef MOZ_X11
  Atom NetWorkareaAtom() { return mNetWorkareaAtom; }
#endif

  // For internal use from signal callback functions
  void RefreshScreens();

 private:
  GdkWindow* mRootWindow;
#ifdef MOZ_X11
  Atom mNetWorkareaAtom;
#endif
};

class ScreenHelperGTK final : public ScreenManager::Helper {
 public:
  ScreenHelperGTK();
  ~ScreenHelperGTK() = default;

  static gint GetGTKMonitorScaleFactor(gint aMonitorNum = 0);

 private:
  UniquePtr<ScreenGetter> mGetter;
};

}  // namespace widget
}  // namespace mozilla

#endif  // mozilla_widget_gtk_ScreenHelperGTK_h
