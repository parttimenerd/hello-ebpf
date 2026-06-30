/** Auto-generated */
package me.bechberger.ebpf.runtime;

import me.bechberger.ebpf.annotations.EnumMember;
import me.bechberger.ebpf.annotations.InlineUnion;
import me.bechberger.ebpf.annotations.Offset;
import me.bechberger.ebpf.annotations.OriginalName;
import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.TrustedPtr;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.type.Enum;
import me.bechberger.ebpf.type.Ptr;
import me.bechberger.ebpf.type.Struct;
import me.bechberger.ebpf.type.TypedEnum;
import me.bechberger.ebpf.type.TypedefBase;
import me.bechberger.ebpf.type.Union;
import org.jetbrains.annotations.Nullable;
import static me.bechberger.ebpf.runtime.AaDefinitions.*;
import static me.bechberger.ebpf.runtime.AafsDefinitions.*;
import static me.bechberger.ebpf.runtime.Aat2870Definitions.*;
import static me.bechberger.ebpf.runtime.AccountDefinitions.*;
import static me.bechberger.ebpf.runtime.AcctDefinitions.*;
import static me.bechberger.ebpf.runtime.AcompDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiphpDefinitions.*;
import static me.bechberger.ebpf.runtime.ActionDefinitions.*;
import static me.bechberger.ebpf.runtime.ActiveDefinitions.*;
import static me.bechberger.ebpf.runtime.AddDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrconfDefinitions.*;
import static me.bechberger.ebpf.runtime.AdjustDefinitions.*;
import static me.bechberger.ebpf.runtime.AdlDefinitions.*;
import static me.bechberger.ebpf.runtime.Adp5520Definitions.*;
import static me.bechberger.ebpf.runtime.AdvisorDefinitions.*;
import static me.bechberger.ebpf.runtime.AeadDefinitions.*;
import static me.bechberger.ebpf.runtime.AerDefinitions.*;
import static me.bechberger.ebpf.runtime.AgpDefinitions.*;
import static me.bechberger.ebpf.runtime.AhashDefinitions.*;
import static me.bechberger.ebpf.runtime.AioDefinitions.*;
import static me.bechberger.ebpf.runtime.AlarmDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocateDefinitions.*;
import static me.bechberger.ebpf.runtime.AmdDefinitions.*;
import static me.bechberger.ebpf.runtime.AmlDefinitions.*;
import static me.bechberger.ebpf.runtime.AnonDefinitions.*;
import static me.bechberger.ebpf.runtime.ApeiDefinitions.*;
import static me.bechberger.ebpf.runtime.ApicDefinitions.*;
import static me.bechberger.ebpf.runtime.ApparmorDefinitions.*;
import static me.bechberger.ebpf.runtime.AppendDefinitions.*;
import static me.bechberger.ebpf.runtime.ApplyDefinitions.*;
import static me.bechberger.ebpf.runtime.ArchDefinitions.*;
import static me.bechberger.ebpf.runtime.ArenaDefinitions.*;
import static me.bechberger.ebpf.runtime.ArpDefinitions.*;
import static me.bechberger.ebpf.runtime.ArrayDefinitions.*;
import static me.bechberger.ebpf.runtime.Asn1Definitions.*;
import static me.bechberger.ebpf.runtime.AssocDefinitions.*;
import static me.bechberger.ebpf.runtime.AsymmetricDefinitions.*;
import static me.bechberger.ebpf.runtime.AsyncDefinitions.*;
import static me.bechberger.ebpf.runtime.AtaDefinitions.*;
import static me.bechberger.ebpf.runtime.AtkbdDefinitions.*;
import static me.bechberger.ebpf.runtime.AtomicDefinitions.*;
import static me.bechberger.ebpf.runtime.AttachDefinitions.*;
import static me.bechberger.ebpf.runtime.AttributeDefinitions.*;
import static me.bechberger.ebpf.runtime.AuditDefinitions.*;
import static me.bechberger.ebpf.runtime.AuxiliaryDefinitions.*;
import static me.bechberger.ebpf.runtime.AvailableDefinitions.*;
import static me.bechberger.ebpf.runtime.AvcDefinitions.*;
import static me.bechberger.ebpf.runtime.AvtabDefinitions.*;
import static me.bechberger.ebpf.runtime.BackingDefinitions.*;
import static me.bechberger.ebpf.runtime.BacklightDefinitions.*;
import static me.bechberger.ebpf.runtime.BadDefinitions.*;
import static me.bechberger.ebpf.runtime.BadblocksDefinitions.*;
import static me.bechberger.ebpf.runtime.BalanceDefinitions.*;
import static me.bechberger.ebpf.runtime.BalloonDefinitions.*;
import static me.bechberger.ebpf.runtime.BdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BdiDefinitions.*;
import static me.bechberger.ebpf.runtime.BgpioDefinitions.*;
import static me.bechberger.ebpf.runtime.BhDefinitions.*;
import static me.bechberger.ebpf.runtime.BindDefinitions.*;
import static me.bechberger.ebpf.runtime.BioDefinitions.*;
import static me.bechberger.ebpf.runtime.BitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.Blake2sDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkcgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkifDefinitions.*;
import static me.bechberger.ebpf.runtime.BlockDefinitions.*;
import static me.bechberger.ebpf.runtime.BloomDefinitions.*;
import static me.bechberger.ebpf.runtime.BootDefinitions.*;
import static me.bechberger.ebpf.runtime.BpfDefinitions.*;
import static me.bechberger.ebpf.runtime.BqlDefinitions.*;
import static me.bechberger.ebpf.runtime.BsgDefinitions.*;
import static me.bechberger.ebpf.runtime.BtfDefinitions.*;
import static me.bechberger.ebpf.runtime.BtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.BtsDefinitions.*;
import static me.bechberger.ebpf.runtime.BufferDefinitions.*;
import static me.bechberger.ebpf.runtime.BuildDefinitions.*;
import static me.bechberger.ebpf.runtime.BusDefinitions.*;
import static me.bechberger.ebpf.runtime.BytDefinitions.*;
import static me.bechberger.ebpf.runtime.CacheDefinitions.*;
import static me.bechberger.ebpf.runtime.CalcDefinitions.*;
import static me.bechberger.ebpf.runtime.CalculateDefinitions.*;
import static me.bechberger.ebpf.runtime.CalipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.CallDefinitions.*;
import static me.bechberger.ebpf.runtime.CanDefinitions.*;
import static me.bechberger.ebpf.runtime.CapDefinitions.*;
import static me.bechberger.ebpf.runtime.CcDefinitions.*;
import static me.bechberger.ebpf.runtime.CdevDefinitions.*;
import static me.bechberger.ebpf.runtime.CdromDefinitions.*;
import static me.bechberger.ebpf.runtime.CeaDefinitions.*;
import static me.bechberger.ebpf.runtime.Cfg80211Definitions.*;
import static me.bechberger.ebpf.runtime.Cgroup1Definitions.*;
import static me.bechberger.ebpf.runtime.CgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ChangeDefinitions.*;
import static me.bechberger.ebpf.runtime.ChargerDefinitions.*;
import static me.bechberger.ebpf.runtime.CheckDefinitions.*;
import static me.bechberger.ebpf.runtime.ChvDefinitions.*;
import static me.bechberger.ebpf.runtime.CipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.ClassDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanupDefinitions.*;
import static me.bechberger.ebpf.runtime.ClearDefinitions.*;
import static me.bechberger.ebpf.runtime.ClkDefinitions.*;
import static me.bechberger.ebpf.runtime.ClockeventsDefinitions.*;
import static me.bechberger.ebpf.runtime.ClocksourceDefinitions.*;
import static me.bechberger.ebpf.runtime.ClosureDefinitions.*;
import static me.bechberger.ebpf.runtime.CmaDefinitions.*;
import static me.bechberger.ebpf.runtime.CmciDefinitions.*;
import static me.bechberger.ebpf.runtime.CmdlineDefinitions.*;
import static me.bechberger.ebpf.runtime.CmisDefinitions.*;
import static me.bechberger.ebpf.runtime.CmosDefinitions.*;
import static me.bechberger.ebpf.runtime.CmpDefinitions.*;
import static me.bechberger.ebpf.runtime.CnDefinitions.*;
import static me.bechberger.ebpf.runtime.CollapseDefinitions.*;
import static me.bechberger.ebpf.runtime.CollectDefinitions.*;
import static me.bechberger.ebpf.runtime.CommonDefinitions.*;
import static me.bechberger.ebpf.runtime.CompactionDefinitions.*;
import static me.bechberger.ebpf.runtime.CompatDefinitions.*;
import static me.bechberger.ebpf.runtime.ComponentDefinitions.*;
import static me.bechberger.ebpf.runtime.ComputeDefinitions.*;
import static me.bechberger.ebpf.runtime.ConDefinitions.*;
import static me.bechberger.ebpf.runtime.CondDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigfsDefinitions.*;
import static me.bechberger.ebpf.runtime.ConsoleDefinitions.*;
import static me.bechberger.ebpf.runtime.ContextDefinitions.*;
import static me.bechberger.ebpf.runtime.ConvertDefinitions.*;
import static me.bechberger.ebpf.runtime.CookieDefinitions.*;
import static me.bechberger.ebpf.runtime.CopyDefinitions.*;
import static me.bechberger.ebpf.runtime.CoreDefinitions.*;
import static me.bechberger.ebpf.runtime.CoredumpDefinitions.*;
import static me.bechberger.ebpf.runtime.CountDefinitions.*;
import static me.bechberger.ebpf.runtime.CpciDefinitions.*;
import static me.bechberger.ebpf.runtime.CperDefinitions.*;
import static me.bechberger.ebpf.runtime.CppcDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuacctDefinitions.*;
import static me.bechberger.ebpf.runtime.CpufreqDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuhpDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuidleDefinitions.*;
import static me.bechberger.ebpf.runtime.CpumaskDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusetDefinitions.*;
import static me.bechberger.ebpf.runtime.CrashDefinitions.*;
import static me.bechberger.ebpf.runtime.CrbDefinitions.*;
import static me.bechberger.ebpf.runtime.Crc64Definitions.*;
import static me.bechberger.ebpf.runtime.CreateDefinitions.*;
import static me.bechberger.ebpf.runtime.CryptoDefinitions.*;
import static me.bechberger.ebpf.runtime.CrystalcoveDefinitions.*;
import static me.bechberger.ebpf.runtime.CssDefinitions.*;
import static me.bechberger.ebpf.runtime.CsumDefinitions.*;
import static me.bechberger.ebpf.runtime.CtDefinitions.*;
import static me.bechberger.ebpf.runtime.CtrlDefinitions.*;
import static me.bechberger.ebpf.runtime.CtxDefinitions.*;
import static me.bechberger.ebpf.runtime.CurrentDefinitions.*;
import static me.bechberger.ebpf.runtime.CxlDefinitions.*;
import static me.bechberger.ebpf.runtime.DDefinitions.*;
import static me.bechberger.ebpf.runtime.Da903xDefinitions.*;
import static me.bechberger.ebpf.runtime.Da9052Definitions.*;
import static me.bechberger.ebpf.runtime.Da9063Definitions.*;
import static me.bechberger.ebpf.runtime.DataDefinitions.*;
import static me.bechberger.ebpf.runtime.DaxDefinitions.*;
import static me.bechberger.ebpf.runtime.DbcDefinitions.*;
import static me.bechberger.ebpf.runtime.DbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbnlDefinitions.*;
import static me.bechberger.ebpf.runtime.DdDefinitions.*;
import static me.bechberger.ebpf.runtime.DdebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DeadlineDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugfsDefinitions.*;
import static me.bechberger.ebpf.runtime.DecDefinitions.*;
import static me.bechberger.ebpf.runtime.DefaultDefinitions.*;
import static me.bechberger.ebpf.runtime.DeferredDefinitions.*;
import static me.bechberger.ebpf.runtime.DeflateDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayacctDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayedDefinitions.*;
import static me.bechberger.ebpf.runtime.DeleteDefinitions.*;
import static me.bechberger.ebpf.runtime.DentryDefinitions.*;
import static me.bechberger.ebpf.runtime.DequeueDefinitions.*;
import static me.bechberger.ebpf.runtime.DescDefinitions.*;
import static me.bechberger.ebpf.runtime.DestroyDefinitions.*;
import static me.bechberger.ebpf.runtime.DetachDefinitions.*;
import static me.bechberger.ebpf.runtime.DevDefinitions.*;
import static me.bechberger.ebpf.runtime.DevcdDefinitions.*;
import static me.bechberger.ebpf.runtime.DevfreqDefinitions.*;
import static me.bechberger.ebpf.runtime.DeviceDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.DevmDefinitions.*;
import static me.bechberger.ebpf.runtime.DevptsDefinitions.*;
import static me.bechberger.ebpf.runtime.DevresDefinitions.*;
import static me.bechberger.ebpf.runtime.DhDefinitions.*;
import static me.bechberger.ebpf.runtime.DimDefinitions.*;
import static me.bechberger.ebpf.runtime.DisableDefinitions.*;
import static me.bechberger.ebpf.runtime.DiskDefinitions.*;
import static me.bechberger.ebpf.runtime.DispatchDefinitions.*;
import static me.bechberger.ebpf.runtime.DisplayidDefinitions.*;
import static me.bechberger.ebpf.runtime.DlDefinitions.*;
import static me.bechberger.ebpf.runtime.DmDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaDefinitions.*;
import static me.bechberger.ebpf.runtime.DmabufDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaengineDefinitions.*;
import static me.bechberger.ebpf.runtime.DmarDefinitions.*;
import static me.bechberger.ebpf.runtime.DmemDefinitions.*;
import static me.bechberger.ebpf.runtime.DmiDefinitions.*;
import static me.bechberger.ebpf.runtime.DnsDefinitions.*;
import static me.bechberger.ebpf.runtime.DoDefinitions.*;
import static me.bechberger.ebpf.runtime.DomainDefinitions.*;
import static me.bechberger.ebpf.runtime.DownDefinitions.*;
import static me.bechberger.ebpf.runtime.DpcDefinitions.*;
import static me.bechberger.ebpf.runtime.DpllDefinitions.*;
import static me.bechberger.ebpf.runtime.DpmDefinitions.*;
import static me.bechberger.ebpf.runtime.DquotDefinitions.*;
import static me.bechberger.ebpf.runtime.DrainDefinitions.*;
import static me.bechberger.ebpf.runtime.DrbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DriverDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmmDefinitions.*;
import static me.bechberger.ebpf.runtime.DropDefinitions.*;
import static me.bechberger.ebpf.runtime.DsaDefinitions.*;
import static me.bechberger.ebpf.runtime.DstDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyconDefinitions.*;
import static me.bechberger.ebpf.runtime.DumpDefinitions.*;
import static me.bechberger.ebpf.runtime.DupDefinitions.*;
import static me.bechberger.ebpf.runtime.DvdDefinitions.*;
import static me.bechberger.ebpf.runtime.DwDefinitions.*;
import static me.bechberger.ebpf.runtime.Dwc2Definitions.*;
import static me.bechberger.ebpf.runtime.DxDefinitions.*;
import static me.bechberger.ebpf.runtime.DynDefinitions.*;
import static me.bechberger.ebpf.runtime.DyneventDefinitions.*;
import static me.bechberger.ebpf.runtime.EafnosupportDefinitions.*;
import static me.bechberger.ebpf.runtime.EarlyDefinitions.*;
import static me.bechberger.ebpf.runtime.EbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.EcDefinitions.*;
import static me.bechberger.ebpf.runtime.EccDefinitions.*;
import static me.bechberger.ebpf.runtime.EcryptfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EdacDefinitions.*;
import static me.bechberger.ebpf.runtime.EddDefinitions.*;
import static me.bechberger.ebpf.runtime.EdidDefinitions.*;
import static me.bechberger.ebpf.runtime.EfiDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EhciDefinitions.*;
import static me.bechberger.ebpf.runtime.ElantsDefinitions.*;
import static me.bechberger.ebpf.runtime.ElevatorDefinitions.*;
import static me.bechberger.ebpf.runtime.ElfDefinitions.*;
import static me.bechberger.ebpf.runtime.ElvDefinitions.*;
import static me.bechberger.ebpf.runtime.EmDefinitions.*;
import static me.bechberger.ebpf.runtime.EmitDefinitions.*;
import static me.bechberger.ebpf.runtime.EnableDefinitions.*;
import static me.bechberger.ebpf.runtime.EndDefinitions.*;
import static me.bechberger.ebpf.runtime.EnqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.EpDefinitions.*;
import static me.bechberger.ebpf.runtime.EprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.ErstDefinitions.*;
import static me.bechberger.ebpf.runtime.EspintcpDefinitions.*;
import static me.bechberger.ebpf.runtime.EthDefinitions.*;
import static me.bechberger.ebpf.runtime.EthnlDefinitions.*;
import static me.bechberger.ebpf.runtime.EthtoolDefinitions.*;
import static me.bechberger.ebpf.runtime.EvdevDefinitions.*;
import static me.bechberger.ebpf.runtime.EventDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfdDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EvmDefinitions.*;
import static me.bechberger.ebpf.runtime.EvtchnDefinitions.*;
import static me.bechberger.ebpf.runtime.ExcDefinitions.*;
import static me.bechberger.ebpf.runtime.ExecmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ExitDefinitions.*;
import static me.bechberger.ebpf.runtime.Ext4Definitions.*;
import static me.bechberger.ebpf.runtime.ExtconDefinitions.*;
import static me.bechberger.ebpf.runtime.FDefinitions.*;
import static me.bechberger.ebpf.runtime.FanotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FatDefinitions.*;
import static me.bechberger.ebpf.runtime.FaultDefinitions.*;
import static me.bechberger.ebpf.runtime.FauxDefinitions.*;
import static me.bechberger.ebpf.runtime.FbDefinitions.*;
import static me.bechberger.ebpf.runtime.FbconDefinitions.*;
import static me.bechberger.ebpf.runtime.FdtDefinitions.*;
import static me.bechberger.ebpf.runtime.FfDefinitions.*;
import static me.bechberger.ebpf.runtime.FgraphDefinitions.*;
import static me.bechberger.ebpf.runtime.Fib4Definitions.*;
import static me.bechberger.ebpf.runtime.Fib6Definitions.*;
import static me.bechberger.ebpf.runtime.FibDefinitions.*;
import static me.bechberger.ebpf.runtime.FifoDefinitions.*;
import static me.bechberger.ebpf.runtime.FileDefinitions.*;
import static me.bechberger.ebpf.runtime.FilemapDefinitions.*;
import static me.bechberger.ebpf.runtime.FilenameDefinitions.*;
import static me.bechberger.ebpf.runtime.FillDefinitions.*;
import static me.bechberger.ebpf.runtime.FilterDefinitions.*;
import static me.bechberger.ebpf.runtime.FindDefinitions.*;
import static me.bechberger.ebpf.runtime.FinishDefinitions.*;
import static me.bechberger.ebpf.runtime.FirmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.FixedDefinitions.*;
import static me.bechberger.ebpf.runtime.FixupDefinitions.*;
import static me.bechberger.ebpf.runtime.FlowDefinitions.*;
import static me.bechberger.ebpf.runtime.FlushDefinitions.*;
import static me.bechberger.ebpf.runtime.FnDefinitions.*;
import static me.bechberger.ebpf.runtime.FolioDefinitions.*;
import static me.bechberger.ebpf.runtime.FollowDefinitions.*;
import static me.bechberger.ebpf.runtime.FopsDefinitions.*;
import static me.bechberger.ebpf.runtime.ForDefinitions.*;
import static me.bechberger.ebpf.runtime.ForceDefinitions.*;
import static me.bechberger.ebpf.runtime.FprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.FpuDefinitions.*;
import static me.bechberger.ebpf.runtime.FredDefinitions.*;
import static me.bechberger.ebpf.runtime.FreeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezerDefinitions.*;
import static me.bechberger.ebpf.runtime.FreqDefinitions.*;
import static me.bechberger.ebpf.runtime.FromDefinitions.*;
import static me.bechberger.ebpf.runtime.FsDefinitions.*;
import static me.bechberger.ebpf.runtime.FscryptDefinitions.*;
import static me.bechberger.ebpf.runtime.FseDefinitions.*;
import static me.bechberger.ebpf.runtime.FsnotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FsverityDefinitions.*;
import static me.bechberger.ebpf.runtime.FtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.FullDefinitions.*;
import static me.bechberger.ebpf.runtime.FunctionDefinitions.*;
import static me.bechberger.ebpf.runtime.FuseDefinitions.*;
import static me.bechberger.ebpf.runtime.FutexDefinitions.*;
import static me.bechberger.ebpf.runtime.FwDefinitions.*;
import static me.bechberger.ebpf.runtime.FwnodeDefinitions.*;
import static me.bechberger.ebpf.runtime.GartDefinitions.*;
import static me.bechberger.ebpf.runtime.GcmDefinitions.*;
import static me.bechberger.ebpf.runtime.GenDefinitions.*;
import static me.bechberger.ebpf.runtime.GenericDefinitions.*;
import static me.bechberger.ebpf.runtime.GenlDefinitions.*;
import static me.bechberger.ebpf.runtime.GenpdDefinitions.*;
import static me.bechberger.ebpf.runtime.GenphyDefinitions.*;
import static me.bechberger.ebpf.runtime.GetDefinitions.*;
import static me.bechberger.ebpf.runtime.GhesDefinitions.*;
import static me.bechberger.ebpf.runtime.GnetDefinitions.*;
import static me.bechberger.ebpf.runtime.GnttabDefinitions.*;
import static me.bechberger.ebpf.runtime.GpioDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiochipDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiodDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiolibDefinitions.*;
import static me.bechberger.ebpf.runtime.GroDefinitions.*;
import static me.bechberger.ebpf.runtime.GroupDefinitions.*;
import static me.bechberger.ebpf.runtime.GupDefinitions.*;
import static me.bechberger.ebpf.runtime.HandleDefinitions.*;
import static me.bechberger.ebpf.runtime.HandshakeDefinitions.*;
import static me.bechberger.ebpf.runtime.HasDefinitions.*;
import static me.bechberger.ebpf.runtime.HashDefinitions.*;
import static me.bechberger.ebpf.runtime.HcdDefinitions.*;
import static me.bechberger.ebpf.runtime.HctxDefinitions.*;
import static me.bechberger.ebpf.runtime.HfiDefinitions.*;
import static me.bechberger.ebpf.runtime.HidDefinitions.*;
import static me.bechberger.ebpf.runtime.HistDefinitions.*;
import static me.bechberger.ebpf.runtime.HmacDefinitions.*;
import static me.bechberger.ebpf.runtime.HmatDefinitions.*;
import static me.bechberger.ebpf.runtime.HmmDefinitions.*;
import static me.bechberger.ebpf.runtime.HookDefinitions.*;
import static me.bechberger.ebpf.runtime.HpetDefinitions.*;
import static me.bechberger.ebpf.runtime.HrtimerDefinitions.*;
import static me.bechberger.ebpf.runtime.HsuDefinitions.*;
import static me.bechberger.ebpf.runtime.HswepDefinitions.*;
import static me.bechberger.ebpf.runtime.HtabDefinitions.*;
import static me.bechberger.ebpf.runtime.HteDefinitions.*;
import static me.bechberger.ebpf.runtime.HubDefinitions.*;
import static me.bechberger.ebpf.runtime.HufDefinitions.*;
import static me.bechberger.ebpf.runtime.HugepageDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbfsDefinitions.*;
import static me.bechberger.ebpf.runtime.HvDefinitions.*;
import static me.bechberger.ebpf.runtime.HvcDefinitions.*;
import static me.bechberger.ebpf.runtime.HwDefinitions.*;
import static me.bechberger.ebpf.runtime.HwlatDefinitions.*;
import static me.bechberger.ebpf.runtime.HwmonDefinitions.*;
import static me.bechberger.ebpf.runtime.HybridDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervisorDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cdevDefinitions.*;
import static me.bechberger.ebpf.runtime.I8042Definitions.*;
import static me.bechberger.ebpf.runtime.Ia32Definitions.*;
import static me.bechberger.ebpf.runtime.IbDefinitions.*;
import static me.bechberger.ebpf.runtime.IccDefinitions.*;
import static me.bechberger.ebpf.runtime.IcmpDefinitions.*;
import static me.bechberger.ebpf.runtime.Icmpv6Definitions.*;
import static me.bechberger.ebpf.runtime.IcxDefinitions.*;
import static me.bechberger.ebpf.runtime.IdleDefinitions.*;
import static me.bechberger.ebpf.runtime.IdrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ieee80211Definitions.*;
import static me.bechberger.ebpf.runtime.IflaDefinitions.*;
import static me.bechberger.ebpf.runtime.Igmp6Definitions.*;
import static me.bechberger.ebpf.runtime.IgmpDefinitions.*;
import static me.bechberger.ebpf.runtime.ImaDefinitions.*;
import static me.bechberger.ebpf.runtime.ImsttfbDefinitions.*;
import static me.bechberger.ebpf.runtime.In6Definitions.*;
import static me.bechberger.ebpf.runtime.InDefinitions.*;
import static me.bechberger.ebpf.runtime.IncDefinitions.*;
import static me.bechberger.ebpf.runtime.Inet6Definitions.*;
import static me.bechberger.ebpf.runtime.InetDefinitions.*;
import static me.bechberger.ebpf.runtime.InitDefinitions.*;
import static me.bechberger.ebpf.runtime.InodeDefinitions.*;
import static me.bechberger.ebpf.runtime.InotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.InputDefinitions.*;
import static me.bechberger.ebpf.runtime.InsertDefinitions.*;
import static me.bechberger.ebpf.runtime.InsnDefinitions.*;
import static me.bechberger.ebpf.runtime.IntDefinitions.*;
import static me.bechberger.ebpf.runtime.IntegrityDefinitions.*;
import static me.bechberger.ebpf.runtime.IntelDefinitions.*;
import static me.bechberger.ebpf.runtime.IntervalDefinitions.*;
import static me.bechberger.ebpf.runtime.InvalidateDefinitions.*;
import static me.bechberger.ebpf.runtime.IoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ioam6Definitions.*;
import static me.bechberger.ebpf.runtime.IoapicDefinitions.*;
import static me.bechberger.ebpf.runtime.IocDefinitions.*;
import static me.bechberger.ebpf.runtime.IocgDefinitions.*;
import static me.bechberger.ebpf.runtime.IoctlDefinitions.*;
import static me.bechberger.ebpf.runtime.IomapDefinitions.*;
import static me.bechberger.ebpf.runtime.IommuDefinitions.*;
import static me.bechberger.ebpf.runtime.IommufdDefinitions.*;
import static me.bechberger.ebpf.runtime.IopfDefinitions.*;
import static me.bechberger.ebpf.runtime.IoremapDefinitions.*;
import static me.bechberger.ebpf.runtime.IosfDefinitions.*;
import static me.bechberger.ebpf.runtime.IovDefinitions.*;
import static me.bechberger.ebpf.runtime.IovaDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip4Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6addrlblDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip6mrDefinitions.*;
import static me.bechberger.ebpf.runtime.IpDefinitions.*;
import static me.bechberger.ebpf.runtime.IpcDefinitions.*;
import static me.bechberger.ebpf.runtime.IpeDefinitions.*;
import static me.bechberger.ebpf.runtime.IpmrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ipv4Definitions.*;
import static me.bechberger.ebpf.runtime.Ipv6Definitions.*;
import static me.bechberger.ebpf.runtime.IrqDefinitions.*;
import static me.bechberger.ebpf.runtime.IrteDefinitions.*;
import static me.bechberger.ebpf.runtime.IsDefinitions.*;
import static me.bechberger.ebpf.runtime.IsaDefinitions.*;
import static me.bechberger.ebpf.runtime.IsolateDefinitions.*;
import static me.bechberger.ebpf.runtime.IterDefinitions.*;
import static me.bechberger.ebpf.runtime.IvbepDefinitions.*;
import static me.bechberger.ebpf.runtime.IwDefinitions.*;
import static me.bechberger.ebpf.runtime.JailhouseDefinitions.*;
import static me.bechberger.ebpf.runtime.Jbd2Definitions.*;
import static me.bechberger.ebpf.runtime.JentDefinitions.*;
import static me.bechberger.ebpf.runtime.JournalDefinitions.*;
import static me.bechberger.ebpf.runtime.JumpDefinitions.*;
import static me.bechberger.ebpf.runtime.KDefinitions.*;
import static me.bechberger.ebpf.runtime.KallsymsDefinitions.*;
import static me.bechberger.ebpf.runtime.KbdDefinitions.*;
import static me.bechberger.ebpf.runtime.KdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KernDefinitions.*;
import static me.bechberger.ebpf.runtime.KernelDefinitions.*;
import static me.bechberger.ebpf.runtime.KernfsDefinitions.*;
import static me.bechberger.ebpf.runtime.KexecDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyctlDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyringDefinitions.*;
import static me.bechberger.ebpf.runtime.KfenceDefinitions.*;
import static me.bechberger.ebpf.runtime.KfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.KfreeDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbocDefinitions.*;
import static me.bechberger.ebpf.runtime.KhoDefinitions.*;
import static me.bechberger.ebpf.runtime.KillDefinitions.*;
import static me.bechberger.ebpf.runtime.KimageDefinitions.*;
import static me.bechberger.ebpf.runtime.KlistDefinitions.*;
import static me.bechberger.ebpf.runtime.KlpDefinitions.*;
import static me.bechberger.ebpf.runtime.KmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.KmemDefinitions.*;
import static me.bechberger.ebpf.runtime.KmsgDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjectDefinitions.*;
import static me.bechberger.ebpf.runtime.KprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.KsmDefinitions.*;
import static me.bechberger.ebpf.runtime.KsysDefinitions.*;
import static me.bechberger.ebpf.runtime.KthreadDefinitions.*;
import static me.bechberger.ebpf.runtime.KtimeDefinitions.*;
import static me.bechberger.ebpf.runtime.KvmDefinitions.*;
import static me.bechberger.ebpf.runtime.L3mdevDefinitions.*;
import static me.bechberger.ebpf.runtime.LabelDefinitions.*;
import static me.bechberger.ebpf.runtime.LandlockDefinitions.*;
import static me.bechberger.ebpf.runtime.LapicDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.LedDefinitions.*;
import static me.bechberger.ebpf.runtime.LedtrigDefinitions.*;
import static me.bechberger.ebpf.runtime.LegacyDefinitions.*;
import static me.bechberger.ebpf.runtime.LinearDefinitions.*;
import static me.bechberger.ebpf.runtime.LineeventDefinitions.*;
import static me.bechberger.ebpf.runtime.LinereqDefinitions.*;
import static me.bechberger.ebpf.runtime.LinkDefinitions.*;
import static me.bechberger.ebpf.runtime.LinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.ListDefinitions.*;
import static me.bechberger.ebpf.runtime.LoadDefinitions.*;
import static me.bechberger.ebpf.runtime.LocalDefinitions.*;
import static me.bechberger.ebpf.runtime.LockDefinitions.*;
import static me.bechberger.ebpf.runtime.LocksDefinitions.*;
import static me.bechberger.ebpf.runtime.LockupDefinitions.*;
import static me.bechberger.ebpf.runtime.LogDefinitions.*;
import static me.bechberger.ebpf.runtime.LookupDefinitions.*;
import static me.bechberger.ebpf.runtime.LoopDefinitions.*;
import static me.bechberger.ebpf.runtime.Lp8788Definitions.*;
import static me.bechberger.ebpf.runtime.LpssDefinitions.*;
import static me.bechberger.ebpf.runtime.LruDefinitions.*;
import static me.bechberger.ebpf.runtime.LskcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.LsmDefinitions.*;
import static me.bechberger.ebpf.runtime.LwtunnelDefinitions.*;
import static me.bechberger.ebpf.runtime.Lz4Definitions.*;
import static me.bechberger.ebpf.runtime.MachineDefinitions.*;
import static me.bechberger.ebpf.runtime.MacsecDefinitions.*;
import static me.bechberger.ebpf.runtime.MadviseDefinitions.*;
import static me.bechberger.ebpf.runtime.MakeDefinitions.*;
import static me.bechberger.ebpf.runtime.MapDefinitions.*;
import static me.bechberger.ebpf.runtime.MapleDefinitions.*;
import static me.bechberger.ebpf.runtime.MarkDefinitions.*;
import static me.bechberger.ebpf.runtime.MasDefinitions.*;
import static me.bechberger.ebpf.runtime.MatchDefinitions.*;
import static me.bechberger.ebpf.runtime.Max310xDefinitions.*;
import static me.bechberger.ebpf.runtime.Max77693Definitions.*;
import static me.bechberger.ebpf.runtime.Max8925Definitions.*;
import static me.bechberger.ebpf.runtime.Max8997Definitions.*;
import static me.bechberger.ebpf.runtime.Max8998Definitions.*;
import static me.bechberger.ebpf.runtime.MaxDefinitions.*;
import static me.bechberger.ebpf.runtime.MayDefinitions.*;
import static me.bechberger.ebpf.runtime.MaybeDefinitions.*;
import static me.bechberger.ebpf.runtime.MbDefinitions.*;
import static me.bechberger.ebpf.runtime.MbmDefinitions.*;
import static me.bechberger.ebpf.runtime.MboxDefinitions.*;
import static me.bechberger.ebpf.runtime.MceDefinitions.*;
import static me.bechberger.ebpf.runtime.McheckDefinitions.*;
import static me.bechberger.ebpf.runtime.MciDefinitions.*;
import static me.bechberger.ebpf.runtime.MctpDefinitions.*;
import static me.bechberger.ebpf.runtime.MctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.MdDefinitions.*;
import static me.bechberger.ebpf.runtime.MddevDefinitions.*;
import static me.bechberger.ebpf.runtime.MdioDefinitions.*;
import static me.bechberger.ebpf.runtime.MdiobusDefinitions.*;
import static me.bechberger.ebpf.runtime.MemDefinitions.*;
import static me.bechberger.ebpf.runtime.MemblockDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcgDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcpyDefinitions.*;
import static me.bechberger.ebpf.runtime.MemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MemoryDefinitions.*;
import static me.bechberger.ebpf.runtime.MempoolDefinitions.*;
import static me.bechberger.ebpf.runtime.MemtypeDefinitions.*;
import static me.bechberger.ebpf.runtime.MigrateDefinitions.*;
import static me.bechberger.ebpf.runtime.MinDefinitions.*;
import static me.bechberger.ebpf.runtime.MipiDefinitions.*;
import static me.bechberger.ebpf.runtime.MiscDefinitions.*;
import static me.bechberger.ebpf.runtime.MldDefinitions.*;
import static me.bechberger.ebpf.runtime.MlsDefinitions.*;
import static me.bechberger.ebpf.runtime.MmDefinitions.*;
import static me.bechberger.ebpf.runtime.MmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MmcDefinitions.*;
import static me.bechberger.ebpf.runtime.MmioDefinitions.*;
import static me.bechberger.ebpf.runtime.MmuDefinitions.*;
import static me.bechberger.ebpf.runtime.MntDefinitions.*;
import static me.bechberger.ebpf.runtime.ModDefinitions.*;
import static me.bechberger.ebpf.runtime.ModuleDefinitions.*;
import static me.bechberger.ebpf.runtime.MountDefinitions.*;
import static me.bechberger.ebpf.runtime.MousedevDefinitions.*;
import static me.bechberger.ebpf.runtime.MoveDefinitions.*;
import static me.bechberger.ebpf.runtime.MpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpageDefinitions.*;
import static me.bechberger.ebpf.runtime.MpiDefinitions.*;
import static me.bechberger.ebpf.runtime.MpihelpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpolDefinitions.*;
import static me.bechberger.ebpf.runtime.MptcpDefinitions.*;
import static me.bechberger.ebpf.runtime.MqDefinitions.*;
import static me.bechberger.ebpf.runtime.MqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.MrDefinitions.*;
import static me.bechberger.ebpf.runtime.MsgDefinitions.*;
import static me.bechberger.ebpf.runtime.MsiDefinitions.*;
import static me.bechberger.ebpf.runtime.MsrDefinitions.*;
import static me.bechberger.ebpf.runtime.MtDefinitions.*;
import static me.bechberger.ebpf.runtime.MtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.MtrrDefinitions.*;
import static me.bechberger.ebpf.runtime.MutexDefinitions.*;
import static me.bechberger.ebpf.runtime.NDefinitions.*;
import static me.bechberger.ebpf.runtime.NapiDefinitions.*;
import static me.bechberger.ebpf.runtime.NativeDefinitions.*;
import static me.bechberger.ebpf.runtime.NbconDefinitions.*;
import static me.bechberger.ebpf.runtime.NcsiDefinitions.*;
import static me.bechberger.ebpf.runtime.NdDefinitions.*;
import static me.bechberger.ebpf.runtime.NdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.NeighDefinitions.*;
import static me.bechberger.ebpf.runtime.NetDefinitions.*;
import static me.bechberger.ebpf.runtime.NetdevDefinitions.*;
import static me.bechberger.ebpf.runtime.NetifDefinitions.*;
import static me.bechberger.ebpf.runtime.NetkitDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlblDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.NetnsDefinitions.*;
import static me.bechberger.ebpf.runtime.NetpollDefinitions.*;
import static me.bechberger.ebpf.runtime.NewDefinitions.*;
import static me.bechberger.ebpf.runtime.NextDefinitions.*;
import static me.bechberger.ebpf.runtime.NexthopDefinitions.*;
import static me.bechberger.ebpf.runtime.NfDefinitions.*;
import static me.bechberger.ebpf.runtime.Nfs4Definitions.*;
import static me.bechberger.ebpf.runtime.NfsDefinitions.*;
import static me.bechberger.ebpf.runtime.NhDefinitions.*;
import static me.bechberger.ebpf.runtime.NhmexDefinitions.*;
import static me.bechberger.ebpf.runtime.Nl80211Definitions.*;
import static me.bechberger.ebpf.runtime.NlaDefinitions.*;
import static me.bechberger.ebpf.runtime.NmiDefinitions.*;
import static me.bechberger.ebpf.runtime.NoDefinitions.*;
import static me.bechberger.ebpf.runtime.NodeDefinitions.*;
import static me.bechberger.ebpf.runtime.NoopDefinitions.*;
import static me.bechberger.ebpf.runtime.NotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.NrDefinitions.*;
import static me.bechberger.ebpf.runtime.NsDefinitions.*;
import static me.bechberger.ebpf.runtime.NullDefinitions.*;
import static me.bechberger.ebpf.runtime.NumaDefinitions.*;
import static me.bechberger.ebpf.runtime.NumachipDefinitions.*;
import static me.bechberger.ebpf.runtime.NvdimmDefinitions.*;
import static me.bechberger.ebpf.runtime.NvmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ObjDefinitions.*;
import static me.bechberger.ebpf.runtime.OctepDefinitions.*;
import static me.bechberger.ebpf.runtime.OdDefinitions.*;
import static me.bechberger.ebpf.runtime.OfDefinitions.*;
import static me.bechberger.ebpf.runtime.OhciDefinitions.*;
import static me.bechberger.ebpf.runtime.OldDefinitions.*;
import static me.bechberger.ebpf.runtime.OomDefinitions.*;
import static me.bechberger.ebpf.runtime.OpalDefinitions.*;
import static me.bechberger.ebpf.runtime.OpenDefinitions.*;
import static me.bechberger.ebpf.runtime.OppDefinitions.*;
import static me.bechberger.ebpf.runtime.OsnoiseDefinitions.*;
import static me.bechberger.ebpf.runtime.P4Definitions.*;
import static me.bechberger.ebpf.runtime.PacketDefinitions.*;
import static me.bechberger.ebpf.runtime.PadataDefinitions.*;
import static me.bechberger.ebpf.runtime.PageDefinitions.*;
import static me.bechberger.ebpf.runtime.PagemapDefinitions.*;
import static me.bechberger.ebpf.runtime.PagesDefinitions.*;
import static me.bechberger.ebpf.runtime.PalmasDefinitions.*;
import static me.bechberger.ebpf.runtime.PanelDefinitions.*;
import static me.bechberger.ebpf.runtime.ParamDefinitions.*;
import static me.bechberger.ebpf.runtime.ParseDefinitions.*;
import static me.bechberger.ebpf.runtime.PartDefinitions.*;
import static me.bechberger.ebpf.runtime.PathDefinitions.*;
import static me.bechberger.ebpf.runtime.PcapDefinitions.*;
import static me.bechberger.ebpf.runtime.PccDefinitions.*;
import static me.bechberger.ebpf.runtime.PciDefinitions.*;
import static me.bechberger.ebpf.runtime.PcibiosDefinitions.*;
import static me.bechberger.ebpf.runtime.PcieDefinitions.*;
import static me.bechberger.ebpf.runtime.PciehpDefinitions.*;
import static me.bechberger.ebpf.runtime.PcimDefinitions.*;
import static me.bechberger.ebpf.runtime.PcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PercpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PerfDefinitions.*;
import static me.bechberger.ebpf.runtime.PfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.PfnDefinitions.*;
import static me.bechberger.ebpf.runtime.PhyDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysdevDefinitions.*;
import static me.bechberger.ebpf.runtime.PickDefinitions.*;
import static me.bechberger.ebpf.runtime.PidDefinitions.*;
import static me.bechberger.ebpf.runtime.PidfsDefinitions.*;
import static me.bechberger.ebpf.runtime.PidsDefinitions.*;
import static me.bechberger.ebpf.runtime.PiixDefinitions.*;
import static me.bechberger.ebpf.runtime.PinDefinitions.*;
import static me.bechberger.ebpf.runtime.PinconfDefinitions.*;
import static me.bechberger.ebpf.runtime.PinctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.PingDefinitions.*;
import static me.bechberger.ebpf.runtime.PinmuxDefinitions.*;
import static me.bechberger.ebpf.runtime.PipeDefinitions.*;
import static me.bechberger.ebpf.runtime.PirqDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs1padDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs7Definitions.*;
import static me.bechberger.ebpf.runtime.PlatformDefinitions.*;
import static me.bechberger.ebpf.runtime.PldmfwDefinitions.*;
import static me.bechberger.ebpf.runtime.Pm860xDefinitions.*;
import static me.bechberger.ebpf.runtime.PmDefinitions.*;
import static me.bechberger.ebpf.runtime.PmcDefinitions.*;
import static me.bechberger.ebpf.runtime.PmdDefinitions.*;
import static me.bechberger.ebpf.runtime.PmuDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpacpiDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicyDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicydbDefinitions.*;
import static me.bechberger.ebpf.runtime.PollDefinitions.*;
import static me.bechberger.ebpf.runtime.Poly1305Definitions.*;
import static me.bechberger.ebpf.runtime.PopulateDefinitions.*;
import static me.bechberger.ebpf.runtime.PortDefinitions.*;
import static me.bechberger.ebpf.runtime.PosixDefinitions.*;
import static me.bechberger.ebpf.runtime.PowerDefinitions.*;
import static me.bechberger.ebpf.runtime.PowercapDefinitions.*;
import static me.bechberger.ebpf.runtime.PppDefinitions.*;
import static me.bechberger.ebpf.runtime.PpsDefinitions.*;
import static me.bechberger.ebpf.runtime.PrDefinitions.*;
import static me.bechberger.ebpf.runtime.PrbDefinitions.*;
import static me.bechberger.ebpf.runtime.PreemptDefinitions.*;
import static me.bechberger.ebpf.runtime.PrepareDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintkDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbeDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbestubDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcessDefinitions.*;
import static me.bechberger.ebpf.runtime.ProfileDefinitions.*;
import static me.bechberger.ebpf.runtime.ProgDefinitions.*;
import static me.bechberger.ebpf.runtime.PropagateDefinitions.*;
import static me.bechberger.ebpf.runtime.ProtoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ps2Definitions.*;
import static me.bechberger.ebpf.runtime.PseDefinitions.*;
import static me.bechberger.ebpf.runtime.PseudoDefinitions.*;
import static me.bechberger.ebpf.runtime.PsiDefinitions.*;
import static me.bechberger.ebpf.runtime.PskbDefinitions.*;
import static me.bechberger.ebpf.runtime.PstoreDefinitions.*;
import static me.bechberger.ebpf.runtime.PtDefinitions.*;
import static me.bechberger.ebpf.runtime.PtdumpDefinitions.*;
import static me.bechberger.ebpf.runtime.PteDefinitions.*;
import static me.bechberger.ebpf.runtime.PtiDefinitions.*;
import static me.bechberger.ebpf.runtime.PtpDefinitions.*;
import static me.bechberger.ebpf.runtime.PtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.PtyDefinitions.*;
import static me.bechberger.ebpf.runtime.PushDefinitions.*;
import static me.bechberger.ebpf.runtime.PutDefinitions.*;
import static me.bechberger.ebpf.runtime.PvDefinitions.*;
import static me.bechberger.ebpf.runtime.PvclockDefinitions.*;
import static me.bechberger.ebpf.runtime.PwmDefinitions.*;
import static me.bechberger.ebpf.runtime.QdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.QhDefinitions.*;
import static me.bechberger.ebpf.runtime.QiDefinitions.*;
import static me.bechberger.ebpf.runtime.QueueDefinitions.*;
import static me.bechberger.ebpf.runtime.QuirkDefinitions.*;
import static me.bechberger.ebpf.runtime.QuotaDefinitions.*;
import static me.bechberger.ebpf.runtime.RadixDefinitions.*;
import static me.bechberger.ebpf.runtime.RamfsDefinitions.*;
import static me.bechberger.ebpf.runtime.RandomDefinitions.*;
import static me.bechberger.ebpf.runtime.RangeDefinitions.*;
import static me.bechberger.ebpf.runtime.Raw6Definitions.*;
import static me.bechberger.ebpf.runtime.RawDefinitions.*;
import static me.bechberger.ebpf.runtime.Rawv6Definitions.*;
import static me.bechberger.ebpf.runtime.RbDefinitions.*;
import static me.bechberger.ebpf.runtime.Rc5t583Definitions.*;
import static me.bechberger.ebpf.runtime.RcuDefinitions.*;
import static me.bechberger.ebpf.runtime.RdevDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmacgDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ReadDefinitions.*;
import static me.bechberger.ebpf.runtime.ReclaimDefinitions.*;
import static me.bechberger.ebpf.runtime.RegDefinitions.*;
import static me.bechberger.ebpf.runtime.RegcacheDefinitions.*;
import static me.bechberger.ebpf.runtime.RegisterDefinitions.*;
import static me.bechberger.ebpf.runtime.RegmapDefinitions.*;
import static me.bechberger.ebpf.runtime.RegulatorDefinitions.*;
import static me.bechberger.ebpf.runtime.RelayDefinitions.*;
import static me.bechberger.ebpf.runtime.ReleaseDefinitions.*;
import static me.bechberger.ebpf.runtime.RemapDefinitions.*;
import static me.bechberger.ebpf.runtime.RemoveDefinitions.*;
import static me.bechberger.ebpf.runtime.ReplaceDefinitions.*;
import static me.bechberger.ebpf.runtime.ReportDefinitions.*;
import static me.bechberger.ebpf.runtime.RequestDefinitions.*;
import static me.bechberger.ebpf.runtime.ResctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.ReserveDefinitions.*;
import static me.bechberger.ebpf.runtime.ResetDefinitions.*;
import static me.bechberger.ebpf.runtime.ResourceDefinitions.*;
import static me.bechberger.ebpf.runtime.RestoreDefinitions.*;
import static me.bechberger.ebpf.runtime.RestrictDefinitions.*;
import static me.bechberger.ebpf.runtime.ResumeDefinitions.*;
import static me.bechberger.ebpf.runtime.RethookDefinitions.*;
import static me.bechberger.ebpf.runtime.ReuseportDefinitions.*;
import static me.bechberger.ebpf.runtime.RfkillDefinitions.*;
import static me.bechberger.ebpf.runtime.RhashtableDefinitions.*;
import static me.bechberger.ebpf.runtime.RingDefinitions.*;
import static me.bechberger.ebpf.runtime.RingbufDefinitions.*;
import static me.bechberger.ebpf.runtime.RioDefinitions.*;
import static me.bechberger.ebpf.runtime.RngDefinitions.*;
import static me.bechberger.ebpf.runtime.RoleDefinitions.*;
import static me.bechberger.ebpf.runtime.RpcDefinitions.*;
import static me.bechberger.ebpf.runtime.RpmDefinitions.*;
import static me.bechberger.ebpf.runtime.RprocDefinitions.*;
import static me.bechberger.ebpf.runtime.RqDefinitions.*;
import static me.bechberger.ebpf.runtime.RsaDefinitions.*;
import static me.bechberger.ebpf.runtime.RsassaDefinitions.*;
import static me.bechberger.ebpf.runtime.RseqDefinitions.*;
import static me.bechberger.ebpf.runtime.RssDefinitions.*;
import static me.bechberger.ebpf.runtime.Rt6Definitions.*;
import static me.bechberger.ebpf.runtime.RtDefinitions.*;
import static me.bechberger.ebpf.runtime.RtcDefinitions.*;
import static me.bechberger.ebpf.runtime.RtmDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnlDefinitions.*;
import static me.bechberger.ebpf.runtime.RunDefinitions.*;
import static me.bechberger.ebpf.runtime.RustDefinitions.*;
import static me.bechberger.ebpf.runtime.RvDefinitions.*;
import static me.bechberger.ebpf.runtime.RxDefinitions.*;
import static me.bechberger.ebpf.runtime.SDefinitions.*;
import static me.bechberger.ebpf.runtime.SataDefinitions.*;
import static me.bechberger.ebpf.runtime.SaveDefinitions.*;
import static me.bechberger.ebpf.runtime.SavedDefinitions.*;
import static me.bechberger.ebpf.runtime.SbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.ScanDefinitions.*;
import static me.bechberger.ebpf.runtime.SccnxpDefinitions.*;
import static me.bechberger.ebpf.runtime.SchedDefinitions.*;
import static me.bechberger.ebpf.runtime.ScheduleDefinitions.*;
import static me.bechberger.ebpf.runtime.ScmDefinitions.*;
import static me.bechberger.ebpf.runtime.ScsiDefinitions.*;
import static me.bechberger.ebpf.runtime.SctpDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.SdDefinitions.*;
import static me.bechberger.ebpf.runtime.SdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SdioDefinitions.*;
import static me.bechberger.ebpf.runtime.SeccompDefinitions.*;
import static me.bechberger.ebpf.runtime.SecurityDefinitions.*;
import static me.bechberger.ebpf.runtime.Seg6Definitions.*;
import static me.bechberger.ebpf.runtime.SelDefinitions.*;
import static me.bechberger.ebpf.runtime.SelectDefinitions.*;
import static me.bechberger.ebpf.runtime.SelinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.SendDefinitions.*;
import static me.bechberger.ebpf.runtime.SeqDefinitions.*;
import static me.bechberger.ebpf.runtime.SerdevDefinitions.*;
import static me.bechberger.ebpf.runtime.Serial8250Definitions.*;
import static me.bechberger.ebpf.runtime.SerialDefinitions.*;
import static me.bechberger.ebpf.runtime.SerioDefinitions.*;
import static me.bechberger.ebpf.runtime.SetDefinitions.*;
import static me.bechberger.ebpf.runtime.SetupDefinitions.*;
import static me.bechberger.ebpf.runtime.SevDefinitions.*;
import static me.bechberger.ebpf.runtime.SfpDefinitions.*;
import static me.bechberger.ebpf.runtime.SgDefinitions.*;
import static me.bechberger.ebpf.runtime.SgxDefinitions.*;
import static me.bechberger.ebpf.runtime.Sha1Definitions.*;
import static me.bechberger.ebpf.runtime.Sha256Definitions.*;
import static me.bechberger.ebpf.runtime.Sha512Definitions.*;
import static me.bechberger.ebpf.runtime.ShashDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ShouldDefinitions.*;
import static me.bechberger.ebpf.runtime.ShowDefinitions.*;
import static me.bechberger.ebpf.runtime.ShpchpDefinitions.*;
import static me.bechberger.ebpf.runtime.ShrinkDefinitions.*;
import static me.bechberger.ebpf.runtime.SidtabDefinitions.*;
import static me.bechberger.ebpf.runtime.SimpleDefinitions.*;
import static me.bechberger.ebpf.runtime.SingleDefinitions.*;
import static me.bechberger.ebpf.runtime.SisDefinitions.*;
import static me.bechberger.ebpf.runtime.SkDefinitions.*;
import static me.bechberger.ebpf.runtime.SkbDefinitions.*;
import static me.bechberger.ebpf.runtime.SkcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.SkxDefinitions.*;
import static me.bechberger.ebpf.runtime.SlabDefinitions.*;
import static me.bechberger.ebpf.runtime.SmackDefinitions.*;
import static me.bechberger.ebpf.runtime.SmeDefinitions.*;
import static me.bechberger.ebpf.runtime.SmkDefinitions.*;
import static me.bechberger.ebpf.runtime.SmpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnapshotDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbepDefinitions.*;
import static me.bechberger.ebpf.runtime.SnpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnrDefinitions.*;
import static me.bechberger.ebpf.runtime.SocDefinitions.*;
import static me.bechberger.ebpf.runtime.SockDefinitions.*;
import static me.bechberger.ebpf.runtime.SoftwareDefinitions.*;
import static me.bechberger.ebpf.runtime.SparseDefinitions.*;
import static me.bechberger.ebpf.runtime.SpiDefinitions.*;
import static me.bechberger.ebpf.runtime.SpliceDefinitions.*;
import static me.bechberger.ebpf.runtime.SplitDefinitions.*;
import static me.bechberger.ebpf.runtime.SprDefinitions.*;
import static me.bechberger.ebpf.runtime.SquashfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SrDefinitions.*;
import static me.bechberger.ebpf.runtime.SramDefinitions.*;
import static me.bechberger.ebpf.runtime.SrcuDefinitions.*;
import static me.bechberger.ebpf.runtime.SriovDefinitions.*;
import static me.bechberger.ebpf.runtime.StackDefinitions.*;
import static me.bechberger.ebpf.runtime.StartDefinitions.*;
import static me.bechberger.ebpf.runtime.StatDefinitions.*;
import static me.bechberger.ebpf.runtime.StaticDefinitions.*;
import static me.bechberger.ebpf.runtime.StatsDefinitions.*;
import static me.bechberger.ebpf.runtime.StopDefinitions.*;
import static me.bechberger.ebpf.runtime.StoreDefinitions.*;
import static me.bechberger.ebpf.runtime.StripeDefinitions.*;
import static me.bechberger.ebpf.runtime.StrpDefinitions.*;
import static me.bechberger.ebpf.runtime.SubflowDefinitions.*;
import static me.bechberger.ebpf.runtime.SubmitDefinitions.*;
import static me.bechberger.ebpf.runtime.SugovDefinitions.*;
import static me.bechberger.ebpf.runtime.SuperDefinitions.*;
import static me.bechberger.ebpf.runtime.SuspendDefinitions.*;
import static me.bechberger.ebpf.runtime.SvcDefinitions.*;
import static me.bechberger.ebpf.runtime.SvsmDefinitions.*;
import static me.bechberger.ebpf.runtime.SwDefinitions.*;
import static me.bechberger.ebpf.runtime.SwapDefinitions.*;
import static me.bechberger.ebpf.runtime.SwiotlbDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SwsuspDefinitions.*;
import static me.bechberger.ebpf.runtime.Sx150xDefinitions.*;
import static me.bechberger.ebpf.runtime.SyncDefinitions.*;
import static me.bechberger.ebpf.runtime.SynchronizeDefinitions.*;
import static me.bechberger.ebpf.runtime.SynthDefinitions.*;
import static me.bechberger.ebpf.runtime.SysDefinitions.*;
import static me.bechberger.ebpf.runtime.SyscallDefinitions.*;
import static me.bechberger.ebpf.runtime.SysctlDefinitions.*;
import static me.bechberger.ebpf.runtime.SysfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SysrqDefinitions.*;
import static me.bechberger.ebpf.runtime.SystemDefinitions.*;
import static me.bechberger.ebpf.runtime.SysvecDefinitions.*;
import static me.bechberger.ebpf.runtime.TargetDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskletDefinitions.*;
import static me.bechberger.ebpf.runtime.TbootDefinitions.*;
import static me.bechberger.ebpf.runtime.TcDefinitions.*;
import static me.bechberger.ebpf.runtime.TcfDefinitions.*;
import static me.bechberger.ebpf.runtime.TcpDefinitions.*;
import static me.bechberger.ebpf.runtime.TcxDefinitions.*;
import static me.bechberger.ebpf.runtime.TdhDefinitions.*;
import static me.bechberger.ebpf.runtime.TdxDefinitions.*;
import static me.bechberger.ebpf.runtime.TestDefinitions.*;
import static me.bechberger.ebpf.runtime.TextDefinitions.*;
import static me.bechberger.ebpf.runtime.TgDefinitions.*;
import static me.bechberger.ebpf.runtime.ThermalDefinitions.*;
import static me.bechberger.ebpf.runtime.ThreadDefinitions.*;
import static me.bechberger.ebpf.runtime.ThrotlDefinitions.*;
import static me.bechberger.ebpf.runtime.TickDefinitions.*;
import static me.bechberger.ebpf.runtime.TimekeepingDefinitions.*;
import static me.bechberger.ebpf.runtime.TimensDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerfdDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerlatDefinitions.*;
import static me.bechberger.ebpf.runtime.TkDefinitions.*;
import static me.bechberger.ebpf.runtime.TlbDefinitions.*;
import static me.bechberger.ebpf.runtime.TlsDefinitions.*;
import static me.bechberger.ebpf.runtime.TmigrDefinitions.*;
import static me.bechberger.ebpf.runtime.TnumDefinitions.*;
import static me.bechberger.ebpf.runtime.ToDefinitions.*;
import static me.bechberger.ebpf.runtime.TomoyoDefinitions.*;
import static me.bechberger.ebpf.runtime.TopologyDefinitions.*;
import static me.bechberger.ebpf.runtime.TouchDefinitions.*;
import static me.bechberger.ebpf.runtime.TpacketDefinitions.*;
import static me.bechberger.ebpf.runtime.Tpm1Definitions.*;
import static me.bechberger.ebpf.runtime.Tpm2Definitions.*;
import static me.bechberger.ebpf.runtime.TpmDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps6586xDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps65910Definitions.*;
import static me.bechberger.ebpf.runtime.TraceDefinitions.*;
import static me.bechberger.ebpf.runtime.TracefsDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceiterDefinitions.*;
import static me.bechberger.ebpf.runtime.TracepointDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.TracerDefinitions.*;
import static me.bechberger.ebpf.runtime.TracingDefinitions.*;
import static me.bechberger.ebpf.runtime.TransportDefinitions.*;
import static me.bechberger.ebpf.runtime.TrieDefinitions.*;
import static me.bechberger.ebpf.runtime.TruncateDefinitions.*;
import static me.bechberger.ebpf.runtime.TrustedDefinitions.*;
import static me.bechberger.ebpf.runtime.TryDefinitions.*;
import static me.bechberger.ebpf.runtime.TscDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyportDefinitions.*;
import static me.bechberger.ebpf.runtime.TunDefinitions.*;
import static me.bechberger.ebpf.runtime.Twl4030Definitions.*;
import static me.bechberger.ebpf.runtime.Twl6040Definitions.*;
import static me.bechberger.ebpf.runtime.TwlDefinitions.*;
import static me.bechberger.ebpf.runtime.TxDefinitions.*;
import static me.bechberger.ebpf.runtime.TypeDefinitions.*;
import static me.bechberger.ebpf.runtime.UDefinitions.*;
import static me.bechberger.ebpf.runtime.UartDefinitions.*;
import static me.bechberger.ebpf.runtime.UbsanDefinitions.*;
import static me.bechberger.ebpf.runtime.Udp4Definitions.*;
import static me.bechberger.ebpf.runtime.Udp6Definitions.*;
import static me.bechberger.ebpf.runtime.UdpDefinitions.*;
import static me.bechberger.ebpf.runtime.Udpv6Definitions.*;
import static me.bechberger.ebpf.runtime.UhciDefinitions.*;
import static me.bechberger.ebpf.runtime.UinputDefinitions.*;
import static me.bechberger.ebpf.runtime.UncoreDefinitions.*;
import static me.bechberger.ebpf.runtime.Univ8250Definitions.*;
import static me.bechberger.ebpf.runtime.UnixDefinitions.*;
import static me.bechberger.ebpf.runtime.UnlockDefinitions.*;
import static me.bechberger.ebpf.runtime.UnmapDefinitions.*;
import static me.bechberger.ebpf.runtime.UnregisterDefinitions.*;
import static me.bechberger.ebpf.runtime.UpdateDefinitions.*;
import static me.bechberger.ebpf.runtime.UprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbdevfsDefinitions.*;
import static me.bechberger.ebpf.runtime.UserDefinitions.*;
import static me.bechberger.ebpf.runtime.UserfaultfdDefinitions.*;
import static me.bechberger.ebpf.runtime.Utf8Definitions.*;
import static me.bechberger.ebpf.runtime.UvDefinitions.*;
import static me.bechberger.ebpf.runtime.UvhDefinitions.*;
import static me.bechberger.ebpf.runtime.ValidateDefinitions.*;
import static me.bechberger.ebpf.runtime.VcDefinitions.*;
import static me.bechberger.ebpf.runtime.VcapDefinitions.*;
import static me.bechberger.ebpf.runtime.VcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.VcsDefinitions.*;
import static me.bechberger.ebpf.runtime.VdsoDefinitions.*;
import static me.bechberger.ebpf.runtime.VerifyDefinitions.*;
import static me.bechberger.ebpf.runtime.VfatDefinitions.*;
import static me.bechberger.ebpf.runtime.VfsDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaconDefinitions.*;
import static me.bechberger.ebpf.runtime.ViaDefinitions.*;
import static me.bechberger.ebpf.runtime.ViommuDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtblkDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtioDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtnetDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtscsiDefinitions.*;
import static me.bechberger.ebpf.runtime.VlanDefinitions.*;
import static me.bechberger.ebpf.runtime.VliDefinitions.*;
import static me.bechberger.ebpf.runtime.VmDefinitions.*;
import static me.bechberger.ebpf.runtime.VmaDefinitions.*;
import static me.bechberger.ebpf.runtime.VmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.VmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmeDefinitions.*;
import static me.bechberger.ebpf.runtime.VmemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmpressureDefinitions.*;
import static me.bechberger.ebpf.runtime.VmstatDefinitions.*;
import static me.bechberger.ebpf.runtime.VmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.VpDefinitions.*;
import static me.bechberger.ebpf.runtime.VringDefinitions.*;
import static me.bechberger.ebpf.runtime.VtDefinitions.*;
import static me.bechberger.ebpf.runtime.WaitDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeupDefinitions.*;
import static me.bechberger.ebpf.runtime.WalkDefinitions.*;
import static me.bechberger.ebpf.runtime.WarnDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchdogDefinitions.*;
import static me.bechberger.ebpf.runtime.WbDefinitions.*;
import static me.bechberger.ebpf.runtime.WbtDefinitions.*;
import static me.bechberger.ebpf.runtime.WiphyDefinitions.*;
import static me.bechberger.ebpf.runtime.WirelessDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm831xDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm8350Definitions.*;
import static me.bechberger.ebpf.runtime.WorkqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.WpDefinitions.*;
import static me.bechberger.ebpf.runtime.WqDefinitions.*;
import static me.bechberger.ebpf.runtime.WriteDefinitions.*;
import static me.bechberger.ebpf.runtime.WritebackDefinitions.*;
import static me.bechberger.ebpf.runtime.WwDefinitions.*;
import static me.bechberger.ebpf.runtime.X2apicDefinitions.*;
import static me.bechberger.ebpf.runtime.X509Definitions.*;
import static me.bechberger.ebpf.runtime.X64Definitions.*;
import static me.bechberger.ebpf.runtime.X86Definitions.*;
import static me.bechberger.ebpf.runtime.XaDefinitions.*;
import static me.bechberger.ebpf.runtime.XasDefinitions.*;
import static me.bechberger.ebpf.runtime.XattrDefinitions.*;
import static me.bechberger.ebpf.runtime.XbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdpDefinitions.*;
import static me.bechberger.ebpf.runtime.XenDefinitions.*;
import static me.bechberger.ebpf.runtime.XenbusDefinitions.*;
import static me.bechberger.ebpf.runtime.XennetDefinitions.*;
import static me.bechberger.ebpf.runtime.XenpfDefinitions.*;
import static me.bechberger.ebpf.runtime.Xfrm4Definitions.*;
import static me.bechberger.ebpf.runtime.Xfrm6Definitions.*;
import static me.bechberger.ebpf.runtime.XfrmDefinitions.*;
import static me.bechberger.ebpf.runtime.XhciDefinitions.*;
import static me.bechberger.ebpf.runtime.XpDefinitions.*;
import static me.bechberger.ebpf.runtime.XsDefinitions.*;
import static me.bechberger.ebpf.runtime.XskDefinitions.*;
import static me.bechberger.ebpf.runtime.XtsDefinitions.*;
import static me.bechberger.ebpf.runtime.XzDefinitions.*;
import static me.bechberger.ebpf.runtime.ZapDefinitions.*;
import static me.bechberger.ebpf.runtime.ZlibDefinitions.*;
import static me.bechberger.ebpf.runtime.ZoneDefinitions.*;
import static me.bechberger.ebpf.runtime.ZpoolDefinitions.*;
import static me.bechberger.ebpf.runtime.ZsDefinitions.*;
import static me.bechberger.ebpf.runtime.ZstdDefinitions.*;
import static me.bechberger.ebpf.runtime.ZswapDefinitions.*;
import static me.bechberger.ebpf.runtime.misc.*;
import static me.bechberger.ebpf.runtime.runtime.*;

/**
 * Generated class for BPF runtime types that start with hdmi
 */
@java.lang.SuppressWarnings("unused")
public final class HdmiDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction("hdmi_audio_infoframe_check((const struct hdmi_audio_infoframe *)$arg1)")
  public static int hdmi_audio_infoframe_check(Ptr<hdmi_audio_infoframe> frame) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int hdmi_audio_infoframe_init(Ptr<hdmi_audio_infoframe> frame) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("hdmi_audio_infoframe_log((const u8 *)$arg1, $arg2, (const struct hdmi_audio_infoframe *)$arg3)")
  public static void hdmi_audio_infoframe_log(String level, Ptr<device> dev,
      Ptr<hdmi_audio_infoframe> frame) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long hdmi_audio_infoframe_pack(
      Ptr<hdmi_audio_infoframe> frame, Ptr<?> buffer, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("hdmi_audio_infoframe_pack_for_dp((const struct hdmi_audio_infoframe *)$arg1, $arg2, $arg3)")
  public static @OriginalName("ssize_t") long hdmi_audio_infoframe_pack_for_dp(
      Ptr<hdmi_audio_infoframe> frame, Ptr<dp_sdp> sdp, char dp_version) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("hdmi_audio_infoframe_pack_only((const struct hdmi_audio_infoframe *)$arg1, $arg2, $arg3)")
  public static @OriginalName("ssize_t") long hdmi_audio_infoframe_pack_only(
      Ptr<hdmi_audio_infoframe> frame, Ptr<?> buffer, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("hdmi_audio_infoframe_pack_payload((const struct hdmi_audio_infoframe *)$arg1, $arg2)")
  public static void hdmi_audio_infoframe_pack_payload(Ptr<hdmi_audio_infoframe> frame,
      Ptr<java.lang.Character> buffer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int hdmi_avi_infoframe_check(Ptr<hdmi_avi_infoframe> frame) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void hdmi_avi_infoframe_init(Ptr<hdmi_avi_infoframe> frame) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("hdmi_avi_infoframe_log((const u8 *)$arg1, $arg2, (const struct hdmi_avi_infoframe *)$arg3)")
  public static void hdmi_avi_infoframe_log(String level, Ptr<device> dev,
      Ptr<hdmi_avi_infoframe> frame) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long hdmi_avi_infoframe_pack(Ptr<hdmi_avi_infoframe> frame,
      Ptr<?> buffer, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("hdmi_avi_infoframe_pack_only((const struct hdmi_avi_infoframe *)$arg1, $arg2, $arg3)")
  public static @OriginalName("ssize_t") long hdmi_avi_infoframe_pack_only(
      Ptr<hdmi_avi_infoframe> frame, Ptr<?> buffer, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("hdmi_avi_infoframe_unpack($arg1, (const void *)$arg2, $arg3)")
  public static int hdmi_avi_infoframe_unpack(Ptr<hdmi_avi_infoframe> frame, Ptr<?> buffer,
      @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int hdmi_drm_infoframe_check(Ptr<hdmi_drm_infoframe> frame) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int hdmi_drm_infoframe_init(Ptr<hdmi_drm_infoframe> frame) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long hdmi_drm_infoframe_pack(Ptr<hdmi_drm_infoframe> frame,
      Ptr<?> buffer, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("hdmi_drm_infoframe_pack_only((const struct hdmi_drm_infoframe *)$arg1, $arg2, $arg3)")
  public static @OriginalName("ssize_t") long hdmi_drm_infoframe_pack_only(
      Ptr<hdmi_drm_infoframe> frame, Ptr<?> buffer, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("hdmi_drm_infoframe_unpack_only($arg1, (const void *)$arg2, $arg3)")
  public static int hdmi_drm_infoframe_unpack_only(Ptr<hdmi_drm_infoframe> frame, Ptr<?> buffer,
      @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("hdmi_infoframe_log((const u8 *)$arg1, $arg2, (const union hdmi_infoframe *)$arg3)")
  public static void hdmi_infoframe_log(String level, Ptr<device> dev, Ptr<hdmi_infoframe> frame) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("hdmi_infoframe_log_header((const u8 *)$arg1, $arg2, (const struct hdmi_any_infoframe *)$arg3)")
  public static void hdmi_infoframe_log_header(String level, Ptr<device> dev,
      Ptr<hdmi_any_infoframe> frame) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long hdmi_infoframe_pack(Ptr<hdmi_infoframe> frame,
      Ptr<?> buffer, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("hdmi_infoframe_pack_only((const union hdmi_infoframe *)$arg1, $arg2, $arg3)")
  public static @OriginalName("ssize_t") long hdmi_infoframe_pack_only(Ptr<hdmi_infoframe> frame,
      Ptr<?> buffer, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("hdmi_infoframe_unpack($arg1, (const void *)$arg2, $arg3)")
  public static int hdmi_infoframe_unpack(Ptr<hdmi_infoframe> frame, Ptr<?> buffer,
      @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long hdmi_read_infoframe(Ptr<file> filp, String ubuf,
      @Unsigned long count, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int hdmi_spd_infoframe_check(Ptr<hdmi_spd_infoframe> frame) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("hdmi_spd_infoframe_init($arg1, (const u8 *)$arg2, (const u8 *)$arg3)")
  public static int hdmi_spd_infoframe_init(Ptr<hdmi_spd_infoframe> frame, String vendor,
      String product) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long hdmi_spd_infoframe_pack(Ptr<hdmi_spd_infoframe> frame,
      Ptr<?> buffer, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("hdmi_spd_infoframe_pack_only((const struct hdmi_spd_infoframe *)$arg1, $arg2, $arg3)")
  public static @OriginalName("ssize_t") long hdmi_spd_infoframe_pack_only(
      Ptr<hdmi_spd_infoframe> frame, Ptr<?> buffer, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int hdmi_vendor_infoframe_check(Ptr<hdmi_vendor_infoframe> frame) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("hdmi_vendor_infoframe_check_only((const struct hdmi_vendor_infoframe *)$arg1)")
  public static int hdmi_vendor_infoframe_check_only(Ptr<hdmi_vendor_infoframe> frame) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int hdmi_vendor_infoframe_init(Ptr<hdmi_vendor_infoframe> frame) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long hdmi_vendor_infoframe_pack(
      Ptr<hdmi_vendor_infoframe> frame, Ptr<?> buffer, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("hdmi_vendor_infoframe_pack_only((const struct hdmi_vendor_infoframe *)$arg1, $arg2, $arg3)")
  public static @OriginalName("ssize_t") long hdmi_vendor_infoframe_pack_only(
      Ptr<hdmi_vendor_infoframe> frame, Ptr<?> buffer, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum hdmi_infoframe_type"
  )
  public enum hdmi_infoframe_type implements Enum<hdmi_infoframe_type>, TypedEnum<hdmi_infoframe_type, java.lang. @Unsigned Integer> {
    /**
     * {@code HDMI_INFOFRAME_TYPE_VENDOR = 129}
     */
    @EnumMember(
        value = 129L,
        name = "HDMI_INFOFRAME_TYPE_VENDOR"
    )
    HDMI_INFOFRAME_TYPE_VENDOR,

    /**
     * {@code HDMI_INFOFRAME_TYPE_AVI = 130}
     */
    @EnumMember(
        value = 130L,
        name = "HDMI_INFOFRAME_TYPE_AVI"
    )
    HDMI_INFOFRAME_TYPE_AVI,

    /**
     * {@code HDMI_INFOFRAME_TYPE_SPD = 131}
     */
    @EnumMember(
        value = 131L,
        name = "HDMI_INFOFRAME_TYPE_SPD"
    )
    HDMI_INFOFRAME_TYPE_SPD,

    /**
     * {@code HDMI_INFOFRAME_TYPE_AUDIO = 132}
     */
    @EnumMember(
        value = 132L,
        name = "HDMI_INFOFRAME_TYPE_AUDIO"
    )
    HDMI_INFOFRAME_TYPE_AUDIO,

    /**
     * {@code HDMI_INFOFRAME_TYPE_DRM = 135}
     */
    @EnumMember(
        value = 135L,
        name = "HDMI_INFOFRAME_TYPE_DRM"
    )
    HDMI_INFOFRAME_TYPE_DRM
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct hdmi_any_infoframe"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class hdmi_any_infoframe extends Struct {
    public hdmi_infoframe_type type;

    public char version;

    public char length;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum hdmi_colorspace"
  )
  public enum hdmi_colorspace implements Enum<hdmi_colorspace>, TypedEnum<hdmi_colorspace, java.lang. @Unsigned Integer> {
    /**
     * {@code HDMI_COLORSPACE_RGB = 0}
     */
    @EnumMember(
        value = 0L,
        name = "HDMI_COLORSPACE_RGB"
    )
    HDMI_COLORSPACE_RGB,

    /**
     * {@code HDMI_COLORSPACE_YUV422 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "HDMI_COLORSPACE_YUV422"
    )
    HDMI_COLORSPACE_YUV422,

    /**
     * {@code HDMI_COLORSPACE_YUV444 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "HDMI_COLORSPACE_YUV444"
    )
    HDMI_COLORSPACE_YUV444,

    /**
     * {@code HDMI_COLORSPACE_YUV420 = 3}
     */
    @EnumMember(
        value = 3L,
        name = "HDMI_COLORSPACE_YUV420"
    )
    HDMI_COLORSPACE_YUV420,

    /**
     * {@code HDMI_COLORSPACE_RESERVED4 = 4}
     */
    @EnumMember(
        value = 4L,
        name = "HDMI_COLORSPACE_RESERVED4"
    )
    HDMI_COLORSPACE_RESERVED4,

    /**
     * {@code HDMI_COLORSPACE_RESERVED5 = 5}
     */
    @EnumMember(
        value = 5L,
        name = "HDMI_COLORSPACE_RESERVED5"
    )
    HDMI_COLORSPACE_RESERVED5,

    /**
     * {@code HDMI_COLORSPACE_RESERVED6 = 6}
     */
    @EnumMember(
        value = 6L,
        name = "HDMI_COLORSPACE_RESERVED6"
    )
    HDMI_COLORSPACE_RESERVED6,

    /**
     * {@code HDMI_COLORSPACE_IDO_DEFINED = 7}
     */
    @EnumMember(
        value = 7L,
        name = "HDMI_COLORSPACE_IDO_DEFINED"
    )
    HDMI_COLORSPACE_IDO_DEFINED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum hdmi_scan_mode"
  )
  public enum hdmi_scan_mode implements Enum<hdmi_scan_mode>, TypedEnum<hdmi_scan_mode, java.lang. @Unsigned Integer> {
    /**
     * {@code HDMI_SCAN_MODE_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "HDMI_SCAN_MODE_NONE"
    )
    HDMI_SCAN_MODE_NONE,

    /**
     * {@code HDMI_SCAN_MODE_OVERSCAN = 1}
     */
    @EnumMember(
        value = 1L,
        name = "HDMI_SCAN_MODE_OVERSCAN"
    )
    HDMI_SCAN_MODE_OVERSCAN,

    /**
     * {@code HDMI_SCAN_MODE_UNDERSCAN = 2}
     */
    @EnumMember(
        value = 2L,
        name = "HDMI_SCAN_MODE_UNDERSCAN"
    )
    HDMI_SCAN_MODE_UNDERSCAN,

    /**
     * {@code HDMI_SCAN_MODE_RESERVED = 3}
     */
    @EnumMember(
        value = 3L,
        name = "HDMI_SCAN_MODE_RESERVED"
    )
    HDMI_SCAN_MODE_RESERVED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum hdmi_colorimetry"
  )
  public enum hdmi_colorimetry implements Enum<hdmi_colorimetry>, TypedEnum<hdmi_colorimetry, java.lang. @Unsigned Integer> {
    /**
     * {@code HDMI_COLORIMETRY_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "HDMI_COLORIMETRY_NONE"
    )
    HDMI_COLORIMETRY_NONE,

    /**
     * {@code HDMI_COLORIMETRY_ITU_601 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "HDMI_COLORIMETRY_ITU_601"
    )
    HDMI_COLORIMETRY_ITU_601,

    /**
     * {@code HDMI_COLORIMETRY_ITU_709 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "HDMI_COLORIMETRY_ITU_709"
    )
    HDMI_COLORIMETRY_ITU_709,

    /**
     * {@code HDMI_COLORIMETRY_EXTENDED = 3}
     */
    @EnumMember(
        value = 3L,
        name = "HDMI_COLORIMETRY_EXTENDED"
    )
    HDMI_COLORIMETRY_EXTENDED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum hdmi_picture_aspect"
  )
  public enum hdmi_picture_aspect implements Enum<hdmi_picture_aspect>, TypedEnum<hdmi_picture_aspect, java.lang. @Unsigned Integer> {
    /**
     * {@code HDMI_PICTURE_ASPECT_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "HDMI_PICTURE_ASPECT_NONE"
    )
    HDMI_PICTURE_ASPECT_NONE,

    /**
     * {@code HDMI_PICTURE_ASPECT_4_3 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "HDMI_PICTURE_ASPECT_4_3"
    )
    HDMI_PICTURE_ASPECT_4_3,

    /**
     * {@code HDMI_PICTURE_ASPECT_16_9 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "HDMI_PICTURE_ASPECT_16_9"
    )
    HDMI_PICTURE_ASPECT_16_9,

    /**
     * {@code HDMI_PICTURE_ASPECT_64_27 = 3}
     */
    @EnumMember(
        value = 3L,
        name = "HDMI_PICTURE_ASPECT_64_27"
    )
    HDMI_PICTURE_ASPECT_64_27,

    /**
     * {@code HDMI_PICTURE_ASPECT_256_135 = 4}
     */
    @EnumMember(
        value = 4L,
        name = "HDMI_PICTURE_ASPECT_256_135"
    )
    HDMI_PICTURE_ASPECT_256_135,

    /**
     * {@code HDMI_PICTURE_ASPECT_RESERVED = 5}
     */
    @EnumMember(
        value = 5L,
        name = "HDMI_PICTURE_ASPECT_RESERVED"
    )
    HDMI_PICTURE_ASPECT_RESERVED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum hdmi_active_aspect"
  )
  public enum hdmi_active_aspect implements Enum<hdmi_active_aspect>, TypedEnum<hdmi_active_aspect, java.lang. @Unsigned Integer> {
    /**
     * {@code HDMI_ACTIVE_ASPECT_16_9_TOP = 2}
     */
    @EnumMember(
        value = 2L,
        name = "HDMI_ACTIVE_ASPECT_16_9_TOP"
    )
    HDMI_ACTIVE_ASPECT_16_9_TOP,

    /**
     * {@code HDMI_ACTIVE_ASPECT_14_9_TOP = 3}
     */
    @EnumMember(
        value = 3L,
        name = "HDMI_ACTIVE_ASPECT_14_9_TOP"
    )
    HDMI_ACTIVE_ASPECT_14_9_TOP,

    /**
     * {@code HDMI_ACTIVE_ASPECT_16_9_CENTER = 4}
     */
    @EnumMember(
        value = 4L,
        name = "HDMI_ACTIVE_ASPECT_16_9_CENTER"
    )
    HDMI_ACTIVE_ASPECT_16_9_CENTER,

    /**
     * {@code HDMI_ACTIVE_ASPECT_PICTURE = 8}
     */
    @EnumMember(
        value = 8L,
        name = "HDMI_ACTIVE_ASPECT_PICTURE"
    )
    HDMI_ACTIVE_ASPECT_PICTURE,

    /**
     * {@code HDMI_ACTIVE_ASPECT_4_3 = 9}
     */
    @EnumMember(
        value = 9L,
        name = "HDMI_ACTIVE_ASPECT_4_3"
    )
    HDMI_ACTIVE_ASPECT_4_3,

    /**
     * {@code HDMI_ACTIVE_ASPECT_16_9 = 10}
     */
    @EnumMember(
        value = 10L,
        name = "HDMI_ACTIVE_ASPECT_16_9"
    )
    HDMI_ACTIVE_ASPECT_16_9,

    /**
     * {@code HDMI_ACTIVE_ASPECT_14_9 = 11}
     */
    @EnumMember(
        value = 11L,
        name = "HDMI_ACTIVE_ASPECT_14_9"
    )
    HDMI_ACTIVE_ASPECT_14_9,

    /**
     * {@code HDMI_ACTIVE_ASPECT_4_3_SP_14_9 = 13}
     */
    @EnumMember(
        value = 13L,
        name = "HDMI_ACTIVE_ASPECT_4_3_SP_14_9"
    )
    HDMI_ACTIVE_ASPECT_4_3_SP_14_9,

    /**
     * {@code HDMI_ACTIVE_ASPECT_16_9_SP_14_9 = 14}
     */
    @EnumMember(
        value = 14L,
        name = "HDMI_ACTIVE_ASPECT_16_9_SP_14_9"
    )
    HDMI_ACTIVE_ASPECT_16_9_SP_14_9,

    /**
     * {@code HDMI_ACTIVE_ASPECT_16_9_SP_4_3 = 15}
     */
    @EnumMember(
        value = 15L,
        name = "HDMI_ACTIVE_ASPECT_16_9_SP_4_3"
    )
    HDMI_ACTIVE_ASPECT_16_9_SP_4_3
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum hdmi_extended_colorimetry"
  )
  public enum hdmi_extended_colorimetry implements Enum<hdmi_extended_colorimetry>, TypedEnum<hdmi_extended_colorimetry, java.lang. @Unsigned Integer> {
    /**
     * {@code HDMI_EXTENDED_COLORIMETRY_XV_YCC_601 = 0}
     */
    @EnumMember(
        value = 0L,
        name = "HDMI_EXTENDED_COLORIMETRY_XV_YCC_601"
    )
    HDMI_EXTENDED_COLORIMETRY_XV_YCC_601,

    /**
     * {@code HDMI_EXTENDED_COLORIMETRY_XV_YCC_709 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "HDMI_EXTENDED_COLORIMETRY_XV_YCC_709"
    )
    HDMI_EXTENDED_COLORIMETRY_XV_YCC_709,

    /**
     * {@code HDMI_EXTENDED_COLORIMETRY_S_YCC_601 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "HDMI_EXTENDED_COLORIMETRY_S_YCC_601"
    )
    HDMI_EXTENDED_COLORIMETRY_S_YCC_601,

    /**
     * {@code HDMI_EXTENDED_COLORIMETRY_OPYCC_601 = 3}
     */
    @EnumMember(
        value = 3L,
        name = "HDMI_EXTENDED_COLORIMETRY_OPYCC_601"
    )
    HDMI_EXTENDED_COLORIMETRY_OPYCC_601,

    /**
     * {@code HDMI_EXTENDED_COLORIMETRY_OPRGB = 4}
     */
    @EnumMember(
        value = 4L,
        name = "HDMI_EXTENDED_COLORIMETRY_OPRGB"
    )
    HDMI_EXTENDED_COLORIMETRY_OPRGB,

    /**
     * {@code HDMI_EXTENDED_COLORIMETRY_BT2020_CONST_LUM = 5}
     */
    @EnumMember(
        value = 5L,
        name = "HDMI_EXTENDED_COLORIMETRY_BT2020_CONST_LUM"
    )
    HDMI_EXTENDED_COLORIMETRY_BT2020_CONST_LUM,

    /**
     * {@code HDMI_EXTENDED_COLORIMETRY_BT2020 = 6}
     */
    @EnumMember(
        value = 6L,
        name = "HDMI_EXTENDED_COLORIMETRY_BT2020"
    )
    HDMI_EXTENDED_COLORIMETRY_BT2020,

    /**
     * {@code HDMI_EXTENDED_COLORIMETRY_RESERVED = 7}
     */
    @EnumMember(
        value = 7L,
        name = "HDMI_EXTENDED_COLORIMETRY_RESERVED"
    )
    HDMI_EXTENDED_COLORIMETRY_RESERVED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum hdmi_quantization_range"
  )
  public enum hdmi_quantization_range implements Enum<hdmi_quantization_range>, TypedEnum<hdmi_quantization_range, java.lang. @Unsigned Integer> {
    /**
     * {@code HDMI_QUANTIZATION_RANGE_DEFAULT = 0}
     */
    @EnumMember(
        value = 0L,
        name = "HDMI_QUANTIZATION_RANGE_DEFAULT"
    )
    HDMI_QUANTIZATION_RANGE_DEFAULT,

    /**
     * {@code HDMI_QUANTIZATION_RANGE_LIMITED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "HDMI_QUANTIZATION_RANGE_LIMITED"
    )
    HDMI_QUANTIZATION_RANGE_LIMITED,

    /**
     * {@code HDMI_QUANTIZATION_RANGE_FULL = 2}
     */
    @EnumMember(
        value = 2L,
        name = "HDMI_QUANTIZATION_RANGE_FULL"
    )
    HDMI_QUANTIZATION_RANGE_FULL,

    /**
     * {@code HDMI_QUANTIZATION_RANGE_RESERVED = 3}
     */
    @EnumMember(
        value = 3L,
        name = "HDMI_QUANTIZATION_RANGE_RESERVED"
    )
    HDMI_QUANTIZATION_RANGE_RESERVED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum hdmi_nups"
  )
  public enum hdmi_nups implements Enum<hdmi_nups>, TypedEnum<hdmi_nups, java.lang. @Unsigned Integer> {
    /**
     * {@code HDMI_NUPS_UNKNOWN = 0}
     */
    @EnumMember(
        value = 0L,
        name = "HDMI_NUPS_UNKNOWN"
    )
    HDMI_NUPS_UNKNOWN,

    /**
     * {@code HDMI_NUPS_HORIZONTAL = 1}
     */
    @EnumMember(
        value = 1L,
        name = "HDMI_NUPS_HORIZONTAL"
    )
    HDMI_NUPS_HORIZONTAL,

    /**
     * {@code HDMI_NUPS_VERTICAL = 2}
     */
    @EnumMember(
        value = 2L,
        name = "HDMI_NUPS_VERTICAL"
    )
    HDMI_NUPS_VERTICAL,

    /**
     * {@code HDMI_NUPS_BOTH = 3}
     */
    @EnumMember(
        value = 3L,
        name = "HDMI_NUPS_BOTH"
    )
    HDMI_NUPS_BOTH
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum hdmi_ycc_quantization_range"
  )
  public enum hdmi_ycc_quantization_range implements Enum<hdmi_ycc_quantization_range>, TypedEnum<hdmi_ycc_quantization_range, java.lang. @Unsigned Integer> {
    /**
     * {@code HDMI_YCC_QUANTIZATION_RANGE_LIMITED = 0}
     */
    @EnumMember(
        value = 0L,
        name = "HDMI_YCC_QUANTIZATION_RANGE_LIMITED"
    )
    HDMI_YCC_QUANTIZATION_RANGE_LIMITED,

    /**
     * {@code HDMI_YCC_QUANTIZATION_RANGE_FULL = 1}
     */
    @EnumMember(
        value = 1L,
        name = "HDMI_YCC_QUANTIZATION_RANGE_FULL"
    )
    HDMI_YCC_QUANTIZATION_RANGE_FULL
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum hdmi_content_type"
  )
  public enum hdmi_content_type implements Enum<hdmi_content_type>, TypedEnum<hdmi_content_type, java.lang. @Unsigned Integer> {
    /**
     * {@code HDMI_CONTENT_TYPE_GRAPHICS = 0}
     */
    @EnumMember(
        value = 0L,
        name = "HDMI_CONTENT_TYPE_GRAPHICS"
    )
    HDMI_CONTENT_TYPE_GRAPHICS,

    /**
     * {@code HDMI_CONTENT_TYPE_PHOTO = 1}
     */
    @EnumMember(
        value = 1L,
        name = "HDMI_CONTENT_TYPE_PHOTO"
    )
    HDMI_CONTENT_TYPE_PHOTO,

    /**
     * {@code HDMI_CONTENT_TYPE_CINEMA = 2}
     */
    @EnumMember(
        value = 2L,
        name = "HDMI_CONTENT_TYPE_CINEMA"
    )
    HDMI_CONTENT_TYPE_CINEMA,

    /**
     * {@code HDMI_CONTENT_TYPE_GAME = 3}
     */
    @EnumMember(
        value = 3L,
        name = "HDMI_CONTENT_TYPE_GAME"
    )
    HDMI_CONTENT_TYPE_GAME
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum hdmi_metadata_type"
  )
  public enum hdmi_metadata_type implements Enum<hdmi_metadata_type>, TypedEnum<hdmi_metadata_type, java.lang. @Unsigned Integer> {
    /**
     * {@code HDMI_STATIC_METADATA_TYPE1 = 0}
     */
    @EnumMember(
        value = 0L,
        name = "HDMI_STATIC_METADATA_TYPE1"
    )
    HDMI_STATIC_METADATA_TYPE1
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum hdmi_eotf"
  )
  public enum hdmi_eotf implements Enum<hdmi_eotf>, TypedEnum<hdmi_eotf, java.lang. @Unsigned Integer> {
    /**
     * {@code HDMI_EOTF_TRADITIONAL_GAMMA_SDR = 0}
     */
    @EnumMember(
        value = 0L,
        name = "HDMI_EOTF_TRADITIONAL_GAMMA_SDR"
    )
    HDMI_EOTF_TRADITIONAL_GAMMA_SDR,

    /**
     * {@code HDMI_EOTF_TRADITIONAL_GAMMA_HDR = 1}
     */
    @EnumMember(
        value = 1L,
        name = "HDMI_EOTF_TRADITIONAL_GAMMA_HDR"
    )
    HDMI_EOTF_TRADITIONAL_GAMMA_HDR,

    /**
     * {@code HDMI_EOTF_SMPTE_ST2084 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "HDMI_EOTF_SMPTE_ST2084"
    )
    HDMI_EOTF_SMPTE_ST2084,

    /**
     * {@code HDMI_EOTF_BT_2100_HLG = 3}
     */
    @EnumMember(
        value = 3L,
        name = "HDMI_EOTF_BT_2100_HLG"
    )
    HDMI_EOTF_BT_2100_HLG
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct hdmi_avi_infoframe"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class hdmi_avi_infoframe extends Struct {
    public hdmi_infoframe_type type;

    public char version;

    public char length;

    public boolean itc;

    public char pixel_repeat;

    public hdmi_colorspace colorspace;

    public hdmi_scan_mode scan_mode;

    public hdmi_colorimetry colorimetry;

    public hdmi_picture_aspect picture_aspect;

    public hdmi_active_aspect active_aspect;

    public hdmi_extended_colorimetry extended_colorimetry;

    public hdmi_quantization_range quantization_range;

    public hdmi_nups nups;

    public char video_code;

    public hdmi_ycc_quantization_range ycc_quantization_range;

    public hdmi_content_type content_type;

    public @Unsigned short top_bar;

    public @Unsigned short bottom_bar;

    public @Unsigned short left_bar;

    public @Unsigned short right_bar;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct hdmi_drm_infoframe"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class hdmi_drm_infoframe extends Struct {
    public hdmi_infoframe_type type;

    public char version;

    public char length;

    public hdmi_eotf eotf;

    public hdmi_metadata_type metadata_type;

    public white_point_of_hdmi_drm_infoframe @Size(3) [] display_primaries;

    public white_point_of_hdmi_drm_infoframe white_point;

    public @Unsigned short max_display_mastering_luminance;

    public @Unsigned short min_display_mastering_luminance;

    public @Unsigned short max_cll;

    public @Unsigned short max_fall;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum hdmi_spd_sdi"
  )
  public enum hdmi_spd_sdi implements Enum<hdmi_spd_sdi>, TypedEnum<hdmi_spd_sdi, java.lang. @Unsigned Integer> {
    /**
     * {@code HDMI_SPD_SDI_UNKNOWN = 0}
     */
    @EnumMember(
        value = 0L,
        name = "HDMI_SPD_SDI_UNKNOWN"
    )
    HDMI_SPD_SDI_UNKNOWN,

    /**
     * {@code HDMI_SPD_SDI_DSTB = 1}
     */
    @EnumMember(
        value = 1L,
        name = "HDMI_SPD_SDI_DSTB"
    )
    HDMI_SPD_SDI_DSTB,

    /**
     * {@code HDMI_SPD_SDI_DVDP = 2}
     */
    @EnumMember(
        value = 2L,
        name = "HDMI_SPD_SDI_DVDP"
    )
    HDMI_SPD_SDI_DVDP,

    /**
     * {@code HDMI_SPD_SDI_DVHS = 3}
     */
    @EnumMember(
        value = 3L,
        name = "HDMI_SPD_SDI_DVHS"
    )
    HDMI_SPD_SDI_DVHS,

    /**
     * {@code HDMI_SPD_SDI_HDDVR = 4}
     */
    @EnumMember(
        value = 4L,
        name = "HDMI_SPD_SDI_HDDVR"
    )
    HDMI_SPD_SDI_HDDVR,

    /**
     * {@code HDMI_SPD_SDI_DVC = 5}
     */
    @EnumMember(
        value = 5L,
        name = "HDMI_SPD_SDI_DVC"
    )
    HDMI_SPD_SDI_DVC,

    /**
     * {@code HDMI_SPD_SDI_DSC = 6}
     */
    @EnumMember(
        value = 6L,
        name = "HDMI_SPD_SDI_DSC"
    )
    HDMI_SPD_SDI_DSC,

    /**
     * {@code HDMI_SPD_SDI_VCD = 7}
     */
    @EnumMember(
        value = 7L,
        name = "HDMI_SPD_SDI_VCD"
    )
    HDMI_SPD_SDI_VCD,

    /**
     * {@code HDMI_SPD_SDI_GAME = 8}
     */
    @EnumMember(
        value = 8L,
        name = "HDMI_SPD_SDI_GAME"
    )
    HDMI_SPD_SDI_GAME,

    /**
     * {@code HDMI_SPD_SDI_PC = 9}
     */
    @EnumMember(
        value = 9L,
        name = "HDMI_SPD_SDI_PC"
    )
    HDMI_SPD_SDI_PC,

    /**
     * {@code HDMI_SPD_SDI_BD = 10}
     */
    @EnumMember(
        value = 10L,
        name = "HDMI_SPD_SDI_BD"
    )
    HDMI_SPD_SDI_BD,

    /**
     * {@code HDMI_SPD_SDI_SACD = 11}
     */
    @EnumMember(
        value = 11L,
        name = "HDMI_SPD_SDI_SACD"
    )
    HDMI_SPD_SDI_SACD,

    /**
     * {@code HDMI_SPD_SDI_HDDVD = 12}
     */
    @EnumMember(
        value = 12L,
        name = "HDMI_SPD_SDI_HDDVD"
    )
    HDMI_SPD_SDI_HDDVD,

    /**
     * {@code HDMI_SPD_SDI_PMP = 13}
     */
    @EnumMember(
        value = 13L,
        name = "HDMI_SPD_SDI_PMP"
    )
    HDMI_SPD_SDI_PMP
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct hdmi_spd_infoframe"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class hdmi_spd_infoframe extends Struct {
    public hdmi_infoframe_type type;

    public char version;

    public char length;

    public char @Size(8) [] vendor;

    public char @Size(16) [] product;

    public hdmi_spd_sdi sdi;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum hdmi_audio_coding_type"
  )
  public enum hdmi_audio_coding_type implements Enum<hdmi_audio_coding_type>, TypedEnum<hdmi_audio_coding_type, java.lang. @Unsigned Integer> {
    /**
     * {@code HDMI_AUDIO_CODING_TYPE_STREAM = 0}
     */
    @EnumMember(
        value = 0L,
        name = "HDMI_AUDIO_CODING_TYPE_STREAM"
    )
    HDMI_AUDIO_CODING_TYPE_STREAM,

    /**
     * {@code HDMI_AUDIO_CODING_TYPE_PCM = 1}
     */
    @EnumMember(
        value = 1L,
        name = "HDMI_AUDIO_CODING_TYPE_PCM"
    )
    HDMI_AUDIO_CODING_TYPE_PCM,

    /**
     * {@code HDMI_AUDIO_CODING_TYPE_AC3 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "HDMI_AUDIO_CODING_TYPE_AC3"
    )
    HDMI_AUDIO_CODING_TYPE_AC3,

    /**
     * {@code HDMI_AUDIO_CODING_TYPE_MPEG1 = 3}
     */
    @EnumMember(
        value = 3L,
        name = "HDMI_AUDIO_CODING_TYPE_MPEG1"
    )
    HDMI_AUDIO_CODING_TYPE_MPEG1,

    /**
     * {@code HDMI_AUDIO_CODING_TYPE_MP3 = 4}
     */
    @EnumMember(
        value = 4L,
        name = "HDMI_AUDIO_CODING_TYPE_MP3"
    )
    HDMI_AUDIO_CODING_TYPE_MP3,

    /**
     * {@code HDMI_AUDIO_CODING_TYPE_MPEG2 = 5}
     */
    @EnumMember(
        value = 5L,
        name = "HDMI_AUDIO_CODING_TYPE_MPEG2"
    )
    HDMI_AUDIO_CODING_TYPE_MPEG2,

    /**
     * {@code HDMI_AUDIO_CODING_TYPE_AAC_LC = 6}
     */
    @EnumMember(
        value = 6L,
        name = "HDMI_AUDIO_CODING_TYPE_AAC_LC"
    )
    HDMI_AUDIO_CODING_TYPE_AAC_LC,

    /**
     * {@code HDMI_AUDIO_CODING_TYPE_DTS = 7}
     */
    @EnumMember(
        value = 7L,
        name = "HDMI_AUDIO_CODING_TYPE_DTS"
    )
    HDMI_AUDIO_CODING_TYPE_DTS,

    /**
     * {@code HDMI_AUDIO_CODING_TYPE_ATRAC = 8}
     */
    @EnumMember(
        value = 8L,
        name = "HDMI_AUDIO_CODING_TYPE_ATRAC"
    )
    HDMI_AUDIO_CODING_TYPE_ATRAC,

    /**
     * {@code HDMI_AUDIO_CODING_TYPE_DSD = 9}
     */
    @EnumMember(
        value = 9L,
        name = "HDMI_AUDIO_CODING_TYPE_DSD"
    )
    HDMI_AUDIO_CODING_TYPE_DSD,

    /**
     * {@code HDMI_AUDIO_CODING_TYPE_EAC3 = 10}
     */
    @EnumMember(
        value = 10L,
        name = "HDMI_AUDIO_CODING_TYPE_EAC3"
    )
    HDMI_AUDIO_CODING_TYPE_EAC3,

    /**
     * {@code HDMI_AUDIO_CODING_TYPE_DTS_HD = 11}
     */
    @EnumMember(
        value = 11L,
        name = "HDMI_AUDIO_CODING_TYPE_DTS_HD"
    )
    HDMI_AUDIO_CODING_TYPE_DTS_HD,

    /**
     * {@code HDMI_AUDIO_CODING_TYPE_MLP = 12}
     */
    @EnumMember(
        value = 12L,
        name = "HDMI_AUDIO_CODING_TYPE_MLP"
    )
    HDMI_AUDIO_CODING_TYPE_MLP,

    /**
     * {@code HDMI_AUDIO_CODING_TYPE_DST = 13}
     */
    @EnumMember(
        value = 13L,
        name = "HDMI_AUDIO_CODING_TYPE_DST"
    )
    HDMI_AUDIO_CODING_TYPE_DST,

    /**
     * {@code HDMI_AUDIO_CODING_TYPE_WMA_PRO = 14}
     */
    @EnumMember(
        value = 14L,
        name = "HDMI_AUDIO_CODING_TYPE_WMA_PRO"
    )
    HDMI_AUDIO_CODING_TYPE_WMA_PRO,

    /**
     * {@code HDMI_AUDIO_CODING_TYPE_CXT = 15}
     */
    @EnumMember(
        value = 15L,
        name = "HDMI_AUDIO_CODING_TYPE_CXT"
    )
    HDMI_AUDIO_CODING_TYPE_CXT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum hdmi_audio_sample_size"
  )
  public enum hdmi_audio_sample_size implements Enum<hdmi_audio_sample_size>, TypedEnum<hdmi_audio_sample_size, java.lang. @Unsigned Integer> {
    /**
     * {@code HDMI_AUDIO_SAMPLE_SIZE_STREAM = 0}
     */
    @EnumMember(
        value = 0L,
        name = "HDMI_AUDIO_SAMPLE_SIZE_STREAM"
    )
    HDMI_AUDIO_SAMPLE_SIZE_STREAM,

    /**
     * {@code HDMI_AUDIO_SAMPLE_SIZE_16 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "HDMI_AUDIO_SAMPLE_SIZE_16"
    )
    HDMI_AUDIO_SAMPLE_SIZE_16,

    /**
     * {@code HDMI_AUDIO_SAMPLE_SIZE_20 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "HDMI_AUDIO_SAMPLE_SIZE_20"
    )
    HDMI_AUDIO_SAMPLE_SIZE_20,

    /**
     * {@code HDMI_AUDIO_SAMPLE_SIZE_24 = 3}
     */
    @EnumMember(
        value = 3L,
        name = "HDMI_AUDIO_SAMPLE_SIZE_24"
    )
    HDMI_AUDIO_SAMPLE_SIZE_24
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum hdmi_audio_sample_frequency"
  )
  public enum hdmi_audio_sample_frequency implements Enum<hdmi_audio_sample_frequency>, TypedEnum<hdmi_audio_sample_frequency, java.lang. @Unsigned Integer> {
    /**
     * {@code HDMI_AUDIO_SAMPLE_FREQUENCY_STREAM = 0}
     */
    @EnumMember(
        value = 0L,
        name = "HDMI_AUDIO_SAMPLE_FREQUENCY_STREAM"
    )
    HDMI_AUDIO_SAMPLE_FREQUENCY_STREAM,

    /**
     * {@code HDMI_AUDIO_SAMPLE_FREQUENCY_32000 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "HDMI_AUDIO_SAMPLE_FREQUENCY_32000"
    )
    HDMI_AUDIO_SAMPLE_FREQUENCY_32000,

    /**
     * {@code HDMI_AUDIO_SAMPLE_FREQUENCY_44100 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "HDMI_AUDIO_SAMPLE_FREQUENCY_44100"
    )
    HDMI_AUDIO_SAMPLE_FREQUENCY_44100,

    /**
     * {@code HDMI_AUDIO_SAMPLE_FREQUENCY_48000 = 3}
     */
    @EnumMember(
        value = 3L,
        name = "HDMI_AUDIO_SAMPLE_FREQUENCY_48000"
    )
    HDMI_AUDIO_SAMPLE_FREQUENCY_48000,

    /**
     * {@code HDMI_AUDIO_SAMPLE_FREQUENCY_88200 = 4}
     */
    @EnumMember(
        value = 4L,
        name = "HDMI_AUDIO_SAMPLE_FREQUENCY_88200"
    )
    HDMI_AUDIO_SAMPLE_FREQUENCY_88200,

    /**
     * {@code HDMI_AUDIO_SAMPLE_FREQUENCY_96000 = 5}
     */
    @EnumMember(
        value = 5L,
        name = "HDMI_AUDIO_SAMPLE_FREQUENCY_96000"
    )
    HDMI_AUDIO_SAMPLE_FREQUENCY_96000,

    /**
     * {@code HDMI_AUDIO_SAMPLE_FREQUENCY_176400 = 6}
     */
    @EnumMember(
        value = 6L,
        name = "HDMI_AUDIO_SAMPLE_FREQUENCY_176400"
    )
    HDMI_AUDIO_SAMPLE_FREQUENCY_176400,

    /**
     * {@code HDMI_AUDIO_SAMPLE_FREQUENCY_192000 = 7}
     */
    @EnumMember(
        value = 7L,
        name = "HDMI_AUDIO_SAMPLE_FREQUENCY_192000"
    )
    HDMI_AUDIO_SAMPLE_FREQUENCY_192000
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum hdmi_audio_coding_type_ext"
  )
  public enum hdmi_audio_coding_type_ext implements Enum<hdmi_audio_coding_type_ext>, TypedEnum<hdmi_audio_coding_type_ext, java.lang. @Unsigned Integer> {
    /**
     * {@code HDMI_AUDIO_CODING_TYPE_EXT_CT = 0}
     */
    @EnumMember(
        value = 0L,
        name = "HDMI_AUDIO_CODING_TYPE_EXT_CT"
    )
    HDMI_AUDIO_CODING_TYPE_EXT_CT,

    /**
     * {@code HDMI_AUDIO_CODING_TYPE_EXT_HE_AAC = 1}
     */
    @EnumMember(
        value = 1L,
        name = "HDMI_AUDIO_CODING_TYPE_EXT_HE_AAC"
    )
    HDMI_AUDIO_CODING_TYPE_EXT_HE_AAC,

    /**
     * {@code HDMI_AUDIO_CODING_TYPE_EXT_HE_AAC_V2 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "HDMI_AUDIO_CODING_TYPE_EXT_HE_AAC_V2"
    )
    HDMI_AUDIO_CODING_TYPE_EXT_HE_AAC_V2,

    /**
     * {@code HDMI_AUDIO_CODING_TYPE_EXT_MPEG_SURROUND = 3}
     */
    @EnumMember(
        value = 3L,
        name = "HDMI_AUDIO_CODING_TYPE_EXT_MPEG_SURROUND"
    )
    HDMI_AUDIO_CODING_TYPE_EXT_MPEG_SURROUND,

    /**
     * {@code HDMI_AUDIO_CODING_TYPE_EXT_MPEG4_HE_AAC = 4}
     */
    @EnumMember(
        value = 4L,
        name = "HDMI_AUDIO_CODING_TYPE_EXT_MPEG4_HE_AAC"
    )
    HDMI_AUDIO_CODING_TYPE_EXT_MPEG4_HE_AAC,

    /**
     * {@code HDMI_AUDIO_CODING_TYPE_EXT_MPEG4_HE_AAC_V2 = 5}
     */
    @EnumMember(
        value = 5L,
        name = "HDMI_AUDIO_CODING_TYPE_EXT_MPEG4_HE_AAC_V2"
    )
    HDMI_AUDIO_CODING_TYPE_EXT_MPEG4_HE_AAC_V2,

    /**
     * {@code HDMI_AUDIO_CODING_TYPE_EXT_MPEG4_AAC_LC = 6}
     */
    @EnumMember(
        value = 6L,
        name = "HDMI_AUDIO_CODING_TYPE_EXT_MPEG4_AAC_LC"
    )
    HDMI_AUDIO_CODING_TYPE_EXT_MPEG4_AAC_LC,

    /**
     * {@code HDMI_AUDIO_CODING_TYPE_EXT_DRA = 7}
     */
    @EnumMember(
        value = 7L,
        name = "HDMI_AUDIO_CODING_TYPE_EXT_DRA"
    )
    HDMI_AUDIO_CODING_TYPE_EXT_DRA,

    /**
     * {@code HDMI_AUDIO_CODING_TYPE_EXT_MPEG4_HE_AAC_SURROUND = 8}
     */
    @EnumMember(
        value = 8L,
        name = "HDMI_AUDIO_CODING_TYPE_EXT_MPEG4_HE_AAC_SURROUND"
    )
    HDMI_AUDIO_CODING_TYPE_EXT_MPEG4_HE_AAC_SURROUND,

    /**
     * {@code HDMI_AUDIO_CODING_TYPE_EXT_MPEG4_AAC_LC_SURROUND = 10}
     */
    @EnumMember(
        value = 10L,
        name = "HDMI_AUDIO_CODING_TYPE_EXT_MPEG4_AAC_LC_SURROUND"
    )
    HDMI_AUDIO_CODING_TYPE_EXT_MPEG4_AAC_LC_SURROUND
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct hdmi_audio_infoframe"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class hdmi_audio_infoframe extends Struct {
    public hdmi_infoframe_type type;

    public char version;

    public char length;

    public char channels;

    public hdmi_audio_coding_type coding_type;

    public hdmi_audio_sample_size sample_size;

    public hdmi_audio_sample_frequency sample_frequency;

    public hdmi_audio_coding_type_ext coding_type_ext;

    public char channel_allocation;

    public char level_shift_value;

    public boolean downmix_inhibit;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct hdmi_vendor_infoframe"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class hdmi_vendor_infoframe extends Struct {
    public hdmi_infoframe_type type;

    public char version;

    public char length;

    public @Unsigned int oui;

    public char vic;

    public hdmi_3d_structure s3d_struct;

    public @Unsigned int s3d_ext_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union hdmi_vendor_any_infoframe"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class hdmi_vendor_any_infoframe extends Union {
    public any_of_hdmi_vendor_any_infoframe any;

    public hdmi_vendor_infoframe hdmi;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union hdmi_infoframe"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class hdmi_infoframe extends Union {
    public hdmi_any_infoframe any;

    public hdmi_avi_infoframe avi;

    public hdmi_spd_infoframe spd;

    public hdmi_vendor_any_infoframe vendor;

    public hdmi_audio_infoframe audio;

    public hdmi_drm_infoframe drm;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum hdmi_3d_structure"
  )
  public enum hdmi_3d_structure implements Enum<hdmi_3d_structure>, TypedEnum<hdmi_3d_structure, java.lang.Integer> {
    /**
     * {@code HDMI_3D_STRUCTURE_INVALID = -1}
     */
    @EnumMember(
        value = -1L,
        name = "HDMI_3D_STRUCTURE_INVALID"
    )
    HDMI_3D_STRUCTURE_INVALID,

    /**
     * {@code HDMI_3D_STRUCTURE_FRAME_PACKING = 0}
     */
    @EnumMember(
        value = 0L,
        name = "HDMI_3D_STRUCTURE_FRAME_PACKING"
    )
    HDMI_3D_STRUCTURE_FRAME_PACKING,

    /**
     * {@code HDMI_3D_STRUCTURE_FIELD_ALTERNATIVE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "HDMI_3D_STRUCTURE_FIELD_ALTERNATIVE"
    )
    HDMI_3D_STRUCTURE_FIELD_ALTERNATIVE,

    /**
     * {@code HDMI_3D_STRUCTURE_LINE_ALTERNATIVE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "HDMI_3D_STRUCTURE_LINE_ALTERNATIVE"
    )
    HDMI_3D_STRUCTURE_LINE_ALTERNATIVE,

    /**
     * {@code HDMI_3D_STRUCTURE_SIDE_BY_SIDE_FULL = 3}
     */
    @EnumMember(
        value = 3L,
        name = "HDMI_3D_STRUCTURE_SIDE_BY_SIDE_FULL"
    )
    HDMI_3D_STRUCTURE_SIDE_BY_SIDE_FULL,

    /**
     * {@code HDMI_3D_STRUCTURE_L_DEPTH = 4}
     */
    @EnumMember(
        value = 4L,
        name = "HDMI_3D_STRUCTURE_L_DEPTH"
    )
    HDMI_3D_STRUCTURE_L_DEPTH,

    /**
     * {@code HDMI_3D_STRUCTURE_L_DEPTH_GFX_GFX_DEPTH = 5}
     */
    @EnumMember(
        value = 5L,
        name = "HDMI_3D_STRUCTURE_L_DEPTH_GFX_GFX_DEPTH"
    )
    HDMI_3D_STRUCTURE_L_DEPTH_GFX_GFX_DEPTH,

    /**
     * {@code HDMI_3D_STRUCTURE_TOP_AND_BOTTOM = 6}
     */
    @EnumMember(
        value = 6L,
        name = "HDMI_3D_STRUCTURE_TOP_AND_BOTTOM"
    )
    HDMI_3D_STRUCTURE_TOP_AND_BOTTOM,

    /**
     * {@code HDMI_3D_STRUCTURE_SIDE_BY_SIDE_HALF = 8}
     */
    @EnumMember(
        value = 8L,
        name = "HDMI_3D_STRUCTURE_SIDE_BY_SIDE_HALF"
    )
    HDMI_3D_STRUCTURE_SIDE_BY_SIDE_HALF
  }
}
